from flask import Flask, request, jsonify
from flask_cors import CORS
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import cv2
import numpy as np
from PIL import Image
import onnxruntime as ort
import re
import json
from werkzeug.utils import secure_filename
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

# India-specific scam patterns
INDIA_SCAM_PATTERNS = {
    'kyc': ['kyc update', 'kyc verification', 'immediate kyc', 'kyc link'],
    'bank': ['your account suspended', 'transaction failed', 'refund pending', 'upi blocked'],
    'lottery': ['congratulations you won', 'lottery prize', '₹10 lakh prize'],
    'govt': ['income tax refund', 'passport verification', 'aadhar update']
}

class ScamDetector:
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained("cardiffnlp/twitter-roberta-base-sentiment-latest")
        self.model = AutoModelForSequenceClassification.from_pretrained("cardiffnlp/twitter-roberta-base-sentiment-latest")
        self.scam_pipe = pipeline("text-classification", 
                                model="nlptown/bert-base-multilingual-uncased-sentiment",
                                tokenizer="nlptown/bert-base-multilingual-uncased-sentiment")
        
    def detect_text_scam(self, text):
        score = 0
        
        # Pattern matching (India-specific)
        text_lower = text.lower()
        for category, patterns in INDIA_SCAM_PATTERNS.items():
            for pattern in patterns:
                if pattern in text_lower:
                    score += 3
        
        # ML classification
        result = self.scam_pipe(text)[0]
        if result['label'] in ['1 star', '2 star'] or result['score'] < 0.3:
            score += 4
            
        # WhatsApp forward detection
        if 'forwarded' in text_lower or 'msg forwarded' in text_lower:
            score += 2
            
        # Suspicious keywords
        suspicious = ['click here', 'verify now', 'urgent', 'immediate action', 'call now']
        for word in suspicious:
            if word in text_lower:
                score += 1
        
        risk_level = "SAFE" if score < 3 else "LOW_RISK" if score < 6 else "HIGH_RISK" if score < 9 else "SCAM"
        return {
            "risk_score": min(score, 10),
            "risk_level": risk_level,
            "patterns_detected": [k for k, v in INDIA_SCAM_PATTERNS.items() if any(p in text_lower for p in v)]
        }

    def detect_image_deepfake(self, image_path):
        # Simple deepfake detection using error level analysis + metadata
        try:
            img = cv2.imread(image_path)
            if img is None:
                return {"risk_level": "UNKNOWN", "confidence": 0.5}
            
            # Error Level Analysis
            ela_img = self.error_level_analysis(img)
            ela_score = np.mean(ela_img)
            
            # Compression artifacts detection
            artifacts = self.detect_compression_artifacts(img)
            
            risk_score = (ela_score * 0.6 + artifacts * 0.4)
            risk_level = "DEEPFAKE" if risk_score > 0.7 else "LIKELY_REAL" if risk_score < 0.3 else "SUSPICIOUS"
            
            return {
                "risk_level": risk_level,
                "confidence": risk_score,
                "ela_score": float(ela_score),
                "artifacts_score": float(artifacts)
            }
        except:
            return {"risk_level": "ERROR", "confidence": 0.0}

    def error_level_analysis(self, img):
        # ELA implementation
        scale = 10
        original = cv2.resize(img, (int(img.shape[1]*scale/100), int(img.shape[0]*scale/100)))
        compressed = cv2.imwrite('temp.jpg', original, [cv2.IMWRITE_JPEG_QUALITY, 90])
        compressed = cv2.imread('temp.jpg')
        original = cv2.resize(original, (compressed.shape[1], compressed.shape[0]))
        
        return cv2.absdiff(original, compressed)

    def detect_compression_artifacts(self, img):
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        return 1.0 - min(laplacian_var / 1000, 1.0)

detector = ScamDetector()

@app.route('/api/scan/text', methods=['POST'])
def scan_text():
    data = request.json
    text = data.get('text', '')
    
    result = detector.detect_text_scam(text)
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "input_type": "text",
        "result": result,
        "suggestions": get_suggestions(result['risk_level'])
    })

@app.route('/api/scan/image', methods=['POST'])
def scan_image():
    if 'image' not in request.files:
        return jsonify({"error": "No image provided"}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "No image selected"}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join('uploads', filename)
    os.makedirs('uploads', exist_ok=True)
    file.save(filepath)
    
    result = detector.detect_image_deepfake(filepath)
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "input_type": "image",
        "result": result,
        "suggestions": ["Verify source", "Check for tampering signs"]
    })

@app.route('/api/scan/whatsapp', methods=['POST'])
def scan_whatsapp():
    data = request.json
    messages = data.get('messages', [])
    
    results = []
    total_risk = 0
    for msg in messages:
        result = detector.detect_text_scam(msg['text'])
        results.append({**result, "message": msg['text']})
        total_risk += result['risk_score']
    
    avg_risk = total_risk / len(messages) if messages else 0
    return jsonify({
        "total_messages": len(messages),
        "avg_risk_score": avg_risk,
        "high_risk_count": len([r for r in results if r['risk_level'] in ['HIGH_RISK', 'SCAM']]),
        "results": results
    })

def get_suggestions(risk_level):
    suggestions = {
        "SAFE": ["Message appears legitimate"],
        "LOW_RISK": ["Be cautious, verify sender"],
        "HIGH_RISK": ["High scam probability - DO NOT click links or share info"],
        "SCAM": ["CONFIRMED SCAM - Report and block immediately"]
    }
    return suggestions.get(risk_level, ["Unknown risk level"])

if __name__ == '__main__':
    app.run(debug=True, port=5000)
