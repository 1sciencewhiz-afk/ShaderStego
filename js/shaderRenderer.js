// Procedural WebGL2 fragment shader (Voronoi fracture + Julia fractal glow)
// used to generate the visual carrier image that masks the hidden data.

import { worstChannelPValue } from './carrierSelfCheck.js';

const VERTEX_SHADER_SOURCE = `#version 300 es
in vec2 aPosition;
void main() {
  gl_Position = vec4(aPosition, 0.0, 1.0);
}`;

const FRAGMENT_SHADER_SOURCE = `#version 300 es
precision highp float;

uniform vec2 uResolution;
uniform float uSeed;

out vec4 outColor;

vec2 hash2(vec2 p) {
  p = vec2(dot(p, vec2(127.1, 311.7)), dot(p, vec2(269.5, 183.3)));
  return fract(sin(p) * 43758.5453123 + uSeed);
}

// Voronoi fracture: distance to the nearest jittered grid point.
float voronoi(vec2 p) {
  vec2 cell = floor(p);
  vec2 local = fract(p);
  float minDist = 1.0;
  for (int y = -1; y <= 1; y++) {
    for (int x = -1; x <= 1; x++) {
      vec2 neighbor = vec2(float(x), float(y));
      vec2 point = hash2(cell + neighbor);
      float dist = length(neighbor + point - local);
      minDist = min(minDist, dist);
    }
  }
  return minDist;
}

// Julia set escape-time fractal, used as a subtle glow overlay.
float juliaGlow(vec2 uv) {
  vec2 z = uv * 3.0 - vec2(1.5, 1.5);
  vec2 c = vec2(-0.4, 0.6);
  for (int i = 0; i < 24; i++) {
    z = vec2(z.x * z.x - z.y * z.y, 2.0 * z.x * z.y) + c;
    if (dot(z, z) > 4.0) {
      return float(i) / 24.0;
    }
  }
  return 0.0;
}

void main() {
  vec2 uv = gl_FragCoord.xy / uResolution.xy;
  vec2 p = uv * 8.0;

  float v1 = voronoi(p);
  float v2 = voronoi(p * 2.3 + 5.0);

  vec3 color = vec3(0.05, 0.07, 0.12);
  color += vec3(0.12, 0.35, 0.65) * (1.0 - v1);
  color += vec3(0.75, 0.20, 0.55) * (1.0 - v2) * 0.5;

  float glow = juliaGlow(uv);
  color += vec3(glow * 0.45, glow * 0.18, glow * 0.55);

  color = pow(clamp(color, 0.0, 1.0), vec3(0.85));
  outColor = vec4(color, 1.0);
}`;

function compileShader(gl, type, source) {
  const shader = gl.createShader(type);
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    const info = gl.getShaderInfoLog(shader);
    gl.deleteShader(shader);
    throw new Error(`Shader compile error: ${info}`);
  }
  return shader;
}

function createProgram(gl, vertexSource, fragmentSource) {
  const vertexShader = compileShader(gl, gl.VERTEX_SHADER, vertexSource);
  const fragmentShader = compileShader(gl, gl.FRAGMENT_SHADER, fragmentSource);

  const program = gl.createProgram();
  gl.attachShader(program, vertexShader);
  gl.attachShader(program, fragmentShader);
  gl.linkProgram(program);

  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    const info = gl.getProgramInfoLog(program);
    throw new Error(`Shader program link error: ${info}`);
  }
  return program;
}

function renderOnce(width, height) {
  const glCanvas = document.createElement('canvas');
  glCanvas.width = width;
  glCanvas.height = height;

  const gl = glCanvas.getContext('webgl2');
  if (!gl) {
    throw new Error('WebGL2 is not supported in this browser.');
  }

  const program = createProgram(gl, VERTEX_SHADER_SOURCE, FRAGMENT_SHADER_SOURCE);
  gl.useProgram(program);

  // Full-viewport quad made of two triangles.
  const positions = new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]);
  const positionBuffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
  gl.bufferData(gl.ARRAY_BUFFER, positions, gl.STATIC_DRAW);

  const positionLocation = gl.getAttribLocation(program, 'aPosition');
  gl.enableVertexAttribArray(positionLocation);
  gl.vertexAttribPointer(positionLocation, 2, gl.FLOAT, false, 0, 0);

  gl.uniform2f(gl.getUniformLocation(program, 'uResolution'), width, height);
  gl.uniform1f(gl.getUniformLocation(program, 'uSeed'), Math.random() * 1000.0);

  gl.viewport(0, 0, width, height);
  gl.clearColor(0, 0, 0, 1);
  gl.clear(gl.COLOR_BUFFER_BIT);
  gl.drawArrays(gl.TRIANGLES, 0, 6);

  const canvas2d = document.createElement('canvas');
  canvas2d.width = width;
  canvas2d.height = height;
  const ctx2d = canvas2d.getContext('2d');
  ctx2d.drawImage(glCanvas, 0, 0);

  return canvas2d;
}

// How many times to re-render (with a fresh random Voronoi seed) if a
// carrier's raw pixel statistics read as chi-square-suspicious before any
// embedding happens. 0.2 sits comfortably under a real scanner's 0.35
// "suspicious" cutoff, leaving margin for the embedding itself to add a
// little more (V1/V2 both already keep that residual small — see README).
const SELF_CHECK_MAX_ATTEMPTS = 20;
const SELF_CHECK_P_THRESHOLD = 0.2;

/**
 * Render the procedural shader at `width` x `height` and return a 2D canvas
 * containing the result. Using a 2D canvas (rather than the WebGL canvas
 * directly) gives predictable top-down pixel ordering for the LSB embedding
 * and PNG export steps.
 *
 * Before returning, the raw (unembedded) output is checked against the same
 * chi-square statistic a steganalysis scanner would compute (see
 * carrierSelfCheck.js) — some carrier dimensions produce visible histogram
 * banding purely from quantizing the shader's smooth gradient, independent
 * of anything embedded later. Since each render uses a fresh random seed,
 * a failing carrier is simply re-rendered; the best of the attempts is used
 * even if every one of them happens to fail the threshold, so this never
 * blocks the caller.
 */
export function renderShaderCanvas(width, height) {
  let best = null;
  let bestP = Infinity;

  for (let attempt = 0; attempt < SELF_CHECK_MAX_ATTEMPTS; attempt++) {
    const canvas2d = renderOnce(width, height);
    const ctx2d = canvas2d.getContext('2d');
    const imageData = ctx2d.getImageData(0, 0, width, height);
    const p = worstChannelPValue(imageData);

    if (p < bestP) {
      best = canvas2d;
      bestP = p;
    }
    if (p <= SELF_CHECK_P_THRESHOLD) {
      return canvas2d;
    }
  }

  return best;
}
