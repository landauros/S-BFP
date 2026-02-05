export default function initShader(gl) {
    const vertexSource = document.getElementById('vertex-shader').innerText;
        const fragmentSource = document.getElementById('fragment-shader').innerText;

        const vertexShader = gl.createShader(gl.VERTEX_SHADER);
        gl.shaderSource(vertexShader, vertexSource);
        gl.compileShader(vertexShader);
        if (!gl.getShaderParameter(vertexShader, gl.COMPILE_STATUS)) {
          console.error('Vertex shader compilation failed:', gl.getShaderInfoLog(vertexShader));
        }
        
        const fragmentShader = gl.createShader(gl.FRAGMENT_SHADER);
        gl.shaderSource(fragmentShader, fragmentSource);
        gl.compileShader(fragmentShader);
        if (!gl.getShaderParameter(fragmentShader, gl.COMPILE_STATUS)) {
          console.error('Fragment shader compilation failed:', gl.getShaderInfoLog(fragmentShader));
        }
        
        const shaderProgram = gl.createProgram();
        gl.attachShader(shaderProgram, vertexShader);
        gl.attachShader(shaderProgram, fragmentShader);
        gl.linkProgram(shaderProgram);
        if (!gl.getProgramParameter(shaderProgram, gl.LINK_STATUS)) {
          console.error('Shader program linking failed:', gl.getProgramInfoLog(shaderProgram));
        }
        
        gl.useProgram(shaderProgram);
        
        return shaderProgram;
}