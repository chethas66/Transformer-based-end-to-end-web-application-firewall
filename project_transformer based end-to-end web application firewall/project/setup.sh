#!/bin/bash

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Transformer-Based WAF Setup Script                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found. Creating from template..."
    cp .env.example .env
    echo "✅ .env file created. Please edit it with your Supabase credentials."
    echo ""
    exit 1
fi

echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed"
echo ""

echo "🧠 Training the Transformer model..."
echo "   This will generate synthetic data and train a DistilBERT model."
echo "   Expected time: 5-10 minutes on CPU, 2-3 minutes on GPU"
echo ""

python waf_training.py

if [ $? -ne 0 ]; then
    echo "❌ Training failed"
    exit 1
fi

echo ""
echo "✅ Model trained and exported to ONNX"
echo ""

echo "🧪 Running component tests..."
echo ""

echo "Testing normalizer..."
python waf_normalizer.py > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "  ✅ Normalizer OK"
else
    echo "  ❌ Normalizer failed"
fi

echo "Testing fast-path filter..."
python waf_fast_path.py > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "  ✅ Fast-path filter OK"
else
    echo "  ❌ Fast-path filter failed"
fi

echo "Testing inference engine..."
python waf_inference.py > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "  ✅ Inference engine OK"
else
    echo "  ❌ Inference engine failed"
fi

echo "Testing decision engine..."
python waf_decision_engine.py > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "  ✅ Decision engine OK"
else
    echo "  ❌ Decision engine failed"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Setup Complete!                                        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "🚀 To start the WAF API:"
echo "   python waf_api.py"
echo ""
echo "📊 To run monitoring:"
echo "   python waf_monitoring.py"
echo ""
echo "🧪 To test the system:"
echo "   python example_client.py"
echo ""
echo "📖 Read the README.md for detailed documentation"
echo ""
