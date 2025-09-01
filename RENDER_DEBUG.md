# Render Deployment Debug Guide

## Current Issue: Dashboard Internal Server Error

The main page works but `/dashboard` returns 500 error.

## Debugging Steps:

### 1. Check Render Logs
- Go to your Render dashboard
- Click on your web service
- Go to "Logs" tab
- Look for error messages when accessing `/dashboard`

### 2. Test Routes
Try these URLs to isolate the issue:
- `https://fintrace-y08p.onrender.com/ping` - Should return "OK"
- `https://fintrace-y08p.onrender.com/test-dashboard` - Should return "Dashboard test route works!"
- `https://fintrace-y08p.onrender.com/test-db` - Test database connection
- `https://fintrace-y08p.onrender.com/debug-env` - Check environment variables
- `https://fintrace-y08p.onrender.com/dashboard` - Now uses simple template for testing

### 3. Common Issues & Solutions

#### Database Connection Issues
- **Problem**: SQLite doesn't work on Render's ephemeral filesystem
- **Solution**: Using PostgreSQL (configured in render.yaml)

#### Memory Issues
- **Problem**: Large HTML template causing memory overflow
- **Solution**: Added error handling and database initialization in dashboard route

#### Template Rendering Issues
- **Problem**: HTML_TEMPLATE might be too large
- **Solution**: Added try-catch around template rendering

### 4. Recent Changes Made

1. **Database Configuration**: 
   - Added PostgreSQL support
   - Conditional SQLAlchemy configuration for dev/prod

2. **Error Handling**:
   - Added try-catch in dashboard route
   - Added test route for debugging

3. **Render Configuration**:
   - Added PostgreSQL database service
   - Removed hardcoded SQLite path

### 5. Next Steps

1. **Deploy Changes**: Push these changes to GitHub
2. **Check Logs**: Monitor Render logs for specific error messages
3. **Test Routes**: Use the test routes to isolate the issue
4. **Database**: Verify PostgreSQL connection is working

### 6. If Still Failing

Check these specific areas:
- Database initialization errors
- Template rendering errors
- Memory allocation issues
- Missing dependencies

### 7. Local Testing

Test locally to ensure changes don't break local development:
```bash
python app.py
# Visit http://localhost:5000/dashboard
```
