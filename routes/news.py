#We saw the possible vulnerability in the code, although
# we were unable to execute the xss attack, we fixed to detect and 
# reject those types of attacks

from flask import Blueprint, render_template, jsonify, request
from markupsafe import escape  # ✅ Corrected import
import requests
import json
import re

news_bp = Blueprint('news', __name__, url_prefix='/apps/news')

# Base URL for the News API
NEWS_API_BASE_URL = "https://saurav.tech/NewsAPI"

# Mapping of our categories to API categories
CATEGORY_MAPPING = {
    'business': 'business',
    'technology': 'technology',
    'world': 'general'
}

DEFAULT_COUNTRY = 'us'

INTERNAL_NEWS = [
    {
        "title": "CONFIDENTIAL: Security Breach Report Q3",
        "description": "Details of recent security incidents affecting customer data. For internal review only.",
        "url": "#internal-only",
        "publishedAt": "2025-01-15T08:30:00Z",
        "urlToImage": ""
    },
    {
        "title": "CONFIDENTIAL: Upcoming Product Launch",
        "description": "Specifications for our next-gen product launch in Q2. Contains proprietary information.",
        "url": "#internal-only",
        "publishedAt": "2025-02-01T10:15:00Z",
        "urlToImage": ""
    }
]

def detect_xss(payload):
    """Detects potential XSS payloads"""
    xss_patterns = [
        r"<script.*?>", r"javascript:", r"onerror=", r"onload=", r"<img.*?onerror=", r"document\.cookie", r"eval\(",
    ]
    for pattern in xss_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False

@news_bp.route('/')
def news_page():
    """Render the news page"""
    return render_template('news.html')

@news_bp.route('/fetch', methods=['GET'])
def fetch_news():
    """Fetch news from the News API with security improvements"""
    try:
        category = request.args.get('category', 'business')
        filter_param = request.args.get('filter', '{}')
        
        # Escape user input to prevent injection attacks
        safe_category = escape(category)
        safe_filter_param = escape(filter_param)
        
        # Check for XSS attempt
        if detect_xss(filter_param):
            return jsonify({'success': False, 'error': "No no no, we don't do that here! 🚫"}), 400
        
        # Validate category
        api_category = CATEGORY_MAPPING.get(safe_category, 'business')
        api_url = f"{NEWS_API_BASE_URL}/top-headlines/category/{api_category}/{DEFAULT_COUNTRY}.json"
        
        print(f"Fetching news from: {api_url}")
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            articles = data.get('articles', [])[:10]  # Limit to 10 articles
            
            try:
                filter_options = json.loads(filter_param)
                print(f"Filter options: {filter_options}")
                
                if filter_options.get('showInternal') == True:
                    print("Adding internal news to results!")
                    articles = INTERNAL_NEWS + articles
            except json.JSONDecodeError:
                return jsonify({'success': False, 'error': "Invalid filter parameter format."}), 400
            
            transformed_data = {
                'success': True,
                'category': safe_category,
                'data': []
            }
            
            for article in articles:
                transformed_data['data'].append({
                    'title': escape(article.get('title', 'No Title')),
                    'content': escape(article.get('description', 'No content available')),
                    'date': escape(article.get('publishedAt', '')),
                    'readMoreUrl': escape(article.get('url', '#')),
                    'imageUrl': escape(article.get('urlToImage', ''))
                })
            
            return jsonify(transformed_data)
        else:
            return jsonify({'success': False, 'error': f'Failed to fetch news. Status code: {response.status_code}'}), response.status_code
    
    except Exception as e:
        print(f"Error fetching news: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

