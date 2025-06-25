#!/usr/bin/env python3
"""
Test script to check email configuration and functionality
"""
import os
import asyncio
from api.utils.email import send_email, send_temporary_password_email, send_password_reset_email

def check_email_config():
    """Check current email configuration"""
    print("=== Email Configuration Check ===")
    
    # Check environment variables
    config_vars = {
        'MAIL_PROVIDER': os.getenv("MAIL_PROVIDER", "smtp"),
        'MAIL_SERVER': os.getenv("MAIL_SERVER"),
        'MAIL_PORT': os.getenv("MAIL_PORT", "587"),
        'MAIL_USERNAME': os.getenv("MAIL_USERNAME"),
        'MAIL_PASSWORD': os.getenv("MAIL_PASSWORD"),
        'MAIL_FROM_ADDRESS': os.getenv("MAIL_FROM_ADDRESS"),
        'MAIL_FROM_NAME': os.getenv("MAIL_FROM_NAME", ""),
        'SENDGRID_API_KEY': os.getenv("SENDGRID_API_KEY"),
    }
    
    for var, value in config_vars.items():
        if value:
            if 'PASSWORD' in var or 'API_KEY' in var:
                print(f"{var}: {'*' * len(str(value))} (configured)")
            else:
                print(f"{var}: {value}")
        else:
            print(f"{var}: NOT SET")
    
    print("\n=== Configuration Analysis ===")
    
    provider = config_vars['MAIL_PROVIDER'].lower()
    if provider == "mock":
        print("✅ Mock email mode is enabled - emails will be logged instead of sent")
        return True
    elif provider == "sendgrid":
        if config_vars['SENDGRID_API_KEY']:
            print("✅ SendGrid configuration looks good")
            return True
        else:
            print("❌ SendGrid API key is missing")
            return False
    elif provider == "smtp":
        required_vars = ['MAIL_SERVER', 'MAIL_USERNAME', 'MAIL_PASSWORD', 'MAIL_FROM_ADDRESS']
        missing_vars = [var for var in required_vars if not config_vars[var]]
        
        if missing_vars:
            print(f"❌ SMTP configuration incomplete. Missing: {', '.join(missing_vars)}")
            return False
        else:
            print("✅ SMTP configuration looks good")
            return True
    else:
        print(f"❌ Unknown email provider: {provider}")
        return False

async def test_email_functions():
    """Test email functions"""
    print("\n=== Testing Email Functions ===")
    
    test_email = "test@example.com"
    test_username = "testuser"
    test_password = "TempPass123!"
    test_reset_key = "test-reset-key-123"
    
    # Test 1: Basic email
    print("Testing basic email...")
    result1 = await send_email(
        to_email=test_email,
        subject="Test Email",
        plain_text="This is a test email",
        html_content="<h1>This is a test email</h1>"
    )
    print(f"Basic email result: {'✅ Success' if result1 else '❌ Failed'}")
    
    # Test 2: Temporary password email
    print("Testing temporary password email...")
    result2 = await send_temporary_password_email(
        email_to=test_email,
        username=test_username,
        temp_password=test_password
    )
    print(f"Temporary password email result: {'✅ Success' if result2 else '❌ Failed'}")
    
    # Test 3: Password reset email
    print("Testing password reset email...")
    result3 = await send_password_reset_email(
        email=test_email,
        username=test_username,
        reset_key=test_reset_key
    )
    print(f"Password reset email result: {'✅ Success' if result3 else '❌ Failed'}")

def show_configuration_options():
    """Show configuration options"""
    print("\n=== Email Configuration Options ===")
    print("\n1. MOCK MODE (Recommended for testing):")
    print("   Set MAIL_PROVIDER=mock in your environment")
    print("   This will log emails instead of sending them")
    
    print("\n2. GMAIL SMTP:")
    print("   MAIL_PROVIDER=smtp")
    print("   MAIL_SERVER=smtp.gmail.com")
    print("   MAIL_PORT=587")
    print("   MAIL_USERNAME=your-email@gmail.com")
    print("   MAIL_PASSWORD=your-app-password")
    print("   MAIL_FROM_ADDRESS=your-email@gmail.com")
    print("   MAIL_FROM_NAME=Field Services Team")
    
    print("\n3. SENDGRID:")
    print("   MAIL_PROVIDER=sendgrid")
    print("   SENDGRID_API_KEY=your-sendgrid-api-key")
    print("   MAIL_FROM_ADDRESS=your-verified-sender@domain.com")
    print("   MAIL_FROM_NAME=Field Services Team")
    
    print("\n4. OTHER SMTP PROVIDERS:")
    print("   MAIL_PROVIDER=smtp")
    print("   MAIL_SERVER=your-smtp-server.com")
    print("   MAIL_PORT=587 (or 465 for SSL)")
    print("   MAIL_USERNAME=your-username")
    print("   MAIL_PASSWORD=your-password")
    print("   MAIL_FROM_ADDRESS=your-email@domain.com")
    print("   MAIL_FROM_NAME=Field Services Team")

async def main():
    """Main function"""
    print("Email Configuration and Testing Tool")
    print("=" * 50)
    
    # Check current configuration
    config_ok = check_email_config()
    
    # Test email functions
    await test_email_functions()
    
    # Show configuration options
    show_configuration_options()
    
    if not config_ok:
        print("\n❌ Email configuration is not complete!")
        print("Please set up the required environment variables.")
    else:
        print("\n✅ Email configuration looks good!")

if __name__ == "__main__":
    asyncio.run(main()) 