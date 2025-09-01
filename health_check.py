def create_health_check():
    """Create a simple health check function"""
    def health_check():
        return "OK", 200
    return health_check
