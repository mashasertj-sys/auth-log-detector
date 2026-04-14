def get_ip_info(ip: str) -> dict:
    """Простая классификация IP без внешних API"""

    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
        return {
            "country": "Local Network",
            "risk_score": 30,
            "type": "private"
        }
    elif ip.startswith('127.'):
        return {
            "country": "Localhost",
            "risk_score": 10,
            "type": "localhost"
        }
    else:
        return {
            "country": "External",
            "risk_score": 70,
            "type": "public"
        }