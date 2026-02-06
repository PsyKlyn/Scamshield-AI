async function scanText() {
    const text = document.getElementById('textInput').value;
    if (!text) return;
    
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = '<div>🔄 Scanning...</div>';
    
    try {
        const response = await fetch('http://localhost:5000/api/scan/text', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text})
        });
        
        const data = await response.json();
        displayResult(data.result);
    } catch(e) {
        resultDiv.innerHTML = '<div style="color:red;">❌ Connection error. Run backend server first.</div>';
    }
}

function displayResult(result) {
    const resultDiv = document.getElementById('result');
    const colorClass = result.risk_level === 'SAFE' ? 'safe' : 'scam';
    const emoji = result.risk_level === 'SAFE' ? '✅' : '⚠️';
    
    resultDiv.innerHTML = `
        <div class="result ${colorClass}">
            <h4>${emoji} ${result.risk_level}</h4>
            <p><strong>Score:</strong> ${result.risk_score}/10</p>
            ${result.patterns_detected.length ? `<p><strong>Detected:</strong> ${result.patterns_detected.join(', ')}</p>` : ''}
        </div>
    `;
}

async function scanImage(event) {
    const file = event.target.files[0];
    const formData = new FormData();
    formData.append('image', file);
    
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = '<div>🔍 Analyzing image...</div>';
    
    try {
        const response = await fetch('http://localhost:5000/api/scan/image', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        displayImageResult(data.result);
    } catch(e) {
        resultDiv.innerHTML = '<div style="color:red;">❌ Error scanning image</div>';
    }
}
