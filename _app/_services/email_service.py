# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart
# from typing import Optional
# import aiosmtplib
# import secrets
# import string
# from datetime import datetime, timedelta
# from jinja2 import Template

# from app.core.config import settings
# from motor.motor_asyncio import AsyncIOMotorDatabase


# class EmailService:
#     def __init__(self, db: AsyncIOMotorDatabase):
#         self.db = db
#         self.invitations_collection = db.user_invitations

#     async def send_user_invitation(
#         self,
#         email: str,
#         invited_by_user_id: str,
#         role: str,
#         store_ids: list[str],
#         permissions: list[str],
#         org_id: str = None
#     ) -> str:
#         """Send user invitation email and store invitation record"""

#         # Get inviter's organization if org_id not provided
#         if not org_id:
#             from bson import ObjectId
#             inviter = await self.db.users.find_one({"_id": ObjectId(invited_by_user_id)})
#             if not inviter:
#                 raise ValueError("Inviter user not found")
#             org_id = str(inviter["organization_id"])

#         # Generate secure invitation token
#         invitation_token = self._generate_invitation_token()

#         # Check for existing pending invitation
#         existing_invitation = await self.invitations_collection.find_one({
#             "email": email,
#             "used": False,
#             "expires_at": {"$gt": datetime.utcnow()}
#         })

#         if existing_invitation:
#             # Update existing invitation instead of creating a new one
#             await self.invitations_collection.update_one(
#                 {"_id": existing_invitation["_id"]},
#                 {
#                     "$set": {
#                         "token": invitation_token,
#                         "role": role,
#                         "store_ids": store_ids,
#                         "permissions": permissions,
#                         "invited_by": invited_by_user_id,
#                         "org_id": org_id,
#                         "created_at": datetime.utcnow(),
#                         "expires_at": datetime.utcnow() + timedelta(days=7),
#                     }
#                 }
#             )
#         else:
#             # Store invitation in database
#             invitation_data = {
#                 "token": invitation_token,
#                 "email": email,
#                 "role": role,
#                 "store_ids": store_ids,
#                 "permissions": permissions,
#                 "invited_by": invited_by_user_id,
#                 "org_id": org_id,
#                 "created_at": datetime.utcnow(),
#                 "expires_at": datetime.utcnow() + timedelta(days=7),  # 7 days expiry
#                 "used": False
#             }
#             await self.invitations_collection.insert_one(invitation_data)

#         # Send email (only if email service is configured)
#         try:
#             await self._send_invitation_email(email, invitation_token)
#         except Exception as e:
#             print(f"Email sending failed, but invitation created: {e}")
#             # Don't fail the whole operation if email fails

#         return invitation_token

#     def _generate_invitation_token(self) -> str:
#         """Generate a secure random token for invitations"""
#         alphabet = string.ascii_letters + string.digits
#         return ''.join(secrets.choice(alphabet) for _ in range(64))

#     async def _send_invitation_email(self, email: str, token: str):
#         """Send the actual invitation email"""

#         # Email template
#         html_template = Template("""
#         <!DOCTYPE html>
#         <html>
#         <head>
#             <meta charset="utf-8">
#             <title>You're Invited to Join {{ company_name }}</title>
#             <style>
#                 body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
#                 .container { max-width: 600px; margin: 0 auto; padding: 20px; }
#                 .header { background: #007bff; color: white; padding: 20px; text-align: center; }
#                 .content { padding: 30px; background: #f9f9f9; }
#                 .button { display: inline-block; padding: 12px 24px; background: #007bff;
#                          color: white; text-decoration: none; border-radius: 5px; }
#                 .footer { padding: 20px; text-align: center; color: #666; font-size: 14px; }
#             </style>
#         </head>
#         <body>
#             <div class="container">
#                 <div class="header">
#                     <h1>Welcome to {{ company_name }}</h1>
#                 </div>
#                 <div class="content">
#                     <h2>You've been invited!</h2>
#                     <p>You have been invited to join <strong>{{ company_name }}</strong> as a team member.</p>
#                     <p>Click the button below to set up your account:</p>
#                     <p style="text-align: center; margin: 30px 0;">
#                         <a href="{{ invitation_url }}" class="button">Accept Invitation</a>
#                     </p>
#                     <p><strong>Note:</strong> This invitation will expire in 7 days.</p>
#                     <p>If you have any questions, please contact your administrator.</p>
#                 </div>
#                 <div class="footer">
#                     <p>This invitation was sent from {{ company_name }}</p>
#                     <p>If you didn't expect this invitation, you can safely ignore this email.</p>
#                 </div>
#             </div>
#         </body>
#         </html>
#         """)

#         # Create invitation URL
#         invitation_url = f"{settings.frontend_url}/auth/accept-invitation?token={token}"

#         # Render email content
#         html_content = html_template.render(
#             company_name=settings.app_name,
#             invitation_url=invitation_url
#         )

#         # Create message
#         message = MIMEMultipart("alternative")
#         message["Subject"] = f"You're Invited to Join {settings.app_name}"
#         message["From"] = settings.smtp_from_email
#         message["To"] = email

#         # Add HTML content
#         html_part = MIMEText(html_content, "html")
#         message.attach(html_part)

#         # Send email
#         try:
#             await aiosmtplib.send(
#                 message,
#                 hostname=settings.smtp_host,
#                 port=settings.smtp_port,
#                 start_tls=settings.smtp_use_tls,
#                 username=settings.smtp_username,
#                 password=settings.smtp_password,
#             )
#             print(f"Invitation email sent successfully to {email}")
#         except Exception as e:
#             print(f"Failed to send invitation email to {email}: {e}")
#             raise

#     async def verify_invitation_token(self, token: str) -> Optional[dict]:
#         """Verify and return invitation data"""
#         invitation = await self.invitations_collection.find_one({
#             "token": token,
#             "used": False,
#             "expires_at": {"$gt": datetime.utcnow()}
#         })

#         return invitation

#     async def mark_invitation_as_used(self, token: str):
#         """Mark invitation as used"""
#         await self.invitations_collection.update_one(
#             {"token": token},
#             {
#                 "$set": {
#                     "used": True,
#                     "used_at": datetime.utcnow()
#                 }
#             }
#         )

#     async def get_pending_invitations(self) -> list[dict]:
#         """Get all pending invitations"""
#         cursor = self.invitations_collection.find({
#             "used": False,
#             "expires_at": {"$gt": datetime.utcnow()}
#         })

#         return await cursor.to_list(None)

#     async def cancel_invitation(self, token: str) -> bool:
#         """Cancel an invitation"""
#         result = await self.invitations_collection.delete_one({"token": token})
#         return result.deleted_count > 0

import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import aiosmtplib
import secrets
import string
from datetime import datetime, timedelta
from jinja2 import Template

from app._core.config import settings
from motor.motor_asyncio import AsyncIOMotorDatabase

# Set up logging
logger = logging.getLogger(__name__)


class EmailService:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db
        self.invitations_collection = db.user_invitations
        self.email_provider = self._detect_email_provider()

    def _detect_email_provider(self) -> str:
        """Detect email provider based on SMTP host"""
        smtp_host = getattr(settings, "smtp_host", "").lower()

        if "gmail.com" in smtp_host:
            return "gmail"
        elif "ethereal.email" in smtp_host:
            return "ethereal"
        elif "sendgrid" in smtp_host:
            return "sendgrid"
        elif "mailgun" in smtp_host:
            return "mailgun"
        elif "brevo" in smtp_host or "sendinblue" in smtp_host:
            return "brevo"
        else:
            return "generic_smtp"

    async def send_user_invitation(
        self,
        email: str,
        invited_by_user_id: str,
        role: str,
        store_ids: list[str],
        permissions: list[str],
        org_id: str = None,
    ) -> str:
        """Send user invitation email and store invitation record"""

        # Get inviter's organization if org_id not provided
        if not org_id:
            from bson import ObjectId
            inviter = await self.db.users.find_one({"_id": ObjectId(invited_by_user_id)})
            if not inviter:
                raise ValueError("Inviter user not found")
            org_id = str(inviter["organization_id"])

        # Generate secure invitation token
        invitation_token = self._generate_invitation_token()

        # Store invitation in database
        invitation_data = {
            "token": invitation_token,
            "email": email,
            "role": role,
            "store_ids": store_ids,
            "permissions": permissions,
            "invited_by": invited_by_user_id,
            "org_id": org_id,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(days=7),  # 7 days expiry
            "used": False,
        }

        await self.invitations_collection.insert_one(invitation_data)

        # Send email
        try:
            await self._send_invitation_email(email, invitation_token, role)
            self._log_success(email)
        except Exception as e:
            logger.error(f"Failed to send invitation email to {email}: {e}")
            print(f"❌ Failed to send invitation email to {email}: {e}")
            raise

        return invitation_token

    def _generate_invitation_token(self) -> str:
        """Generate a secure random token for invitations"""
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(64))

    def _log_success(self, email: str):
        """Log success message based on email provider"""
        logger.info(
            f"Invitation email sent successfully to {email} via {self.email_provider}"
        )

        if self.email_provider == "gmail":
            print(f"✅ Gmail: Invitation sent to {email}")
        elif self.email_provider == "ethereal":
            print(f"✅ Ethereal: Invitation sent to {email}")
            print(f"🔗 View at: https://ethereal.email/messages")
            print(f"👤 Login: {settings.smtp_username}")
        else:
            print(f"✅ {self.email_provider.title()}: Invitation sent to {email}")

    async def _send_invitation_email(
        self, email: str, token: str, role: str = "Team Member"
    ):
        """Send the actual invitation email"""

        # Validate required settings
        self._validate_smtp_config()

        # Get email template based on provider
        html_content = self._get_email_template(email, token, role)

        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = self._get_email_subject()
        message["From"] = settings.smtp_from_email
        message["To"] = email
        message["Reply-To"] = settings.smtp_from_email

        # Add HTML content
        html_part = MIMEText(html_content, "html", "utf-8")
        message.attach(html_part)

        # Send email with provider-specific configuration
        try:
            await self._send_via_smtp(message)

        except aiosmtplib.SMTPAuthenticationError as e:
            error_msg = self._get_auth_error_message()
            logger.error(f"SMTP Authentication failed: {e}")
            print(f"❌ {error_msg}")
            raise Exception(
                "Email authentication failed. Please check your credentials."
            )

        except aiosmtplib.SMTPConnectError as e:
            logger.error(f"SMTP Connection failed: {e}")
            print(f"❌ Failed to connect to {self.email_provider} server")
            raise Exception("Failed to connect to email server.")

        except Exception as e:
            logger.error(f"Unexpected email error: {e}")
            print(f"❌ Unexpected error: {e}")
            raise

    def _validate_smtp_config(self):
        """Validate SMTP configuration based on provider"""
        required_settings = ["smtp_host", "smtp_port", "smtp_from_email"]

        # Check if authentication is needed
        if self.email_provider != "local":
            required_settings.extend(["smtp_username", "smtp_password"])

        for setting in required_settings:
            if not hasattr(settings, setting) or not getattr(settings, setting):
                raise ValueError(f"Missing required SMTP setting: {setting}")

    def _get_auth_error_message(self) -> str:
        """Get provider-specific authentication error message"""
        if self.email_provider == "gmail":
            return (
                "Gmail authentication failed. Make sure you're using an App Password, not your regular password. "
                "Enable 2FA and generate an App Password in Google Account settings."
            )
        elif self.email_provider == "ethereal":
            return "Ethereal authentication failed. Check your username and password from https://ethereal.email/"
        elif self.email_provider == "sendgrid":
            return "SendGrid authentication failed. Use 'apikey' as username and your API key as password."
        else:
            return f"{self.email_provider.title()} authentication failed. Please check your credentials."

    def _get_email_subject(self) -> str:
        """Get email subject based on provider"""
        app_name = getattr(settings, "app_name", "Our Team")

        if self.email_provider == "ethereal":
            return f"🧪 [TEST] You're Invited to Join {app_name}!"
        else:
            return f"You're Invited to Join {app_name}!"

    def _get_email_template(self, email: str, token: str, role: str) -> str:
        """Get email template based on provider"""

        # Base template
        if self.email_provider == "ethereal":
            template_str = self._get_ethereal_template()
        else:
            template_str = self._get_production_template()

        html_template = Template(template_str)

        # Create invitation URL
        invitation_url = f"{settings.frontend_url}/auth/accept-invitation?token={token}"

        # Template variables
        template_vars = {
            "company_name": getattr(settings, "app_name", "Your Company"),
            "invitation_url": invitation_url,
            "recipient_email": email,
            "role": role,
            "current_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "expiry_date": (datetime.utcnow() + timedelta(days=7)).strftime("%Y-%m-%d"),
        }

        # Add provider-specific variables
        if self.email_provider == "ethereal":
            template_vars.update(
                {
                    "token": token,
                    "provider": "Ethereal Email (Development)",
                    "view_url": "https://ethereal.email/messages",
                }
            )

        return html_template.render(**template_vars)

    def _get_production_template(self) -> str:
        """Get production email template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>You're Invited to Join {{ company_name }}</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    line-height: 1.6; 
                    color: #333; 
                    margin: 0; 
                    padding: 0; 
                    background-color: #f4f4f4;
                }
                .container { 
                    max-width: 600px; 
                    margin: 20px auto; 
                    background: white;
                    border-radius: 10px;
                    overflow: hidden;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }
                .header { 
                    background: linear-gradient(135deg, #007bff, #0056b3); 
                    color: white; 
                    padding: 30px 20px; 
                    text-align: center; 
                }
                .header h1 {
                    margin: 0;
                    font-size: 28px;
                    font-weight: 300;
                }
                .content { 
                    padding: 40px 30px; 
                    background: #ffffff;
                }
                .content h2 {
                    color: #007bff;
                    margin-top: 0;
                    font-size: 24px;
                    font-weight: 400;
                }
                .invitation-details {
                    background: #f8f9fa;
                    padding: 20px;
                    border-left: 4px solid #007bff;
                    margin: 20px 0;
                    border-radius: 4px;
                }
                .button { 
                    display: inline-block; 
                    padding: 15px 30px; 
                    background: linear-gradient(135deg, #007bff, #0056b3); 
                    color: white !important; 
                    text-decoration: none; 
                    border-radius: 25px; 
                    font-weight: bold;
                    font-size: 16px;
                    box-shadow: 0 2px 4px rgba(0, 123, 255, 0.3);
                }
                .footer { 
                    padding: 30px 20px; 
                    text-align: center; 
                    color: #666; 
                    font-size: 14px; 
                    background: #f8f9fa;
                    border-top: 1px solid #dee2e6;
                }
                @media (max-width: 600px) {
                    .container { margin: 10px; }
                    .content { padding: 20px; }
                    .header { padding: 20px; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to {{ company_name }}</h1>
                </div>
                <div class="content">
                    <h2>🎉 You've been invited!</h2>
                    <p>Great news! You have been invited to join <strong>{{ company_name }}</strong> as a <strong>{{ role }}</strong>.</p>
                    
                    <div class="invitation-details">
                        <p><strong>📧 Email:</strong> {{ recipient_email }}</p>
                        <p><strong>👤 Role:</strong> {{ role }}</p>
                        <p><strong>⏰ Expires:</strong> {{ expiry_date }}</p>
                    </div>
                    
                    <p>Click the button below to accept your invitation and set up your account:</p>
                    
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{{ invitation_url }}" class="button">Accept Invitation</a>
                    </p>
                    
                    <p><strong>⚠️ Important:</strong> This invitation will expire in 7 days.</p>
                    <p>If you have any questions, please contact your administrator.</p>
                </div>
                <div class="footer">
                    <p>This invitation was sent from <strong>{{ company_name }}</strong></p>
                    <p>If you didn't expect this invitation, you can safely ignore this email.</p>
                </div>
            </div>
        </body>
        </html>
        """

    def _get_ethereal_template(self) -> str:
        """Get Ethereal-specific email template with debug info"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>🧪 TEST - You're Invited to Join {{ company_name }}</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    line-height: 1.6; 
                    color: #333; 
                    margin: 0; 
                    padding: 0; 
                    background-color: #f4f4f4;
                }
                .container { 
                    max-width: 600px; 
                    margin: 20px auto; 
                    background: white;
                    border-radius: 10px;
                    overflow: hidden;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    border: 3px solid #28a745;
                }
                .test-banner {
                    background: #28a745;
                    color: white;
                    padding: 10px;
                    text-align: center;
                    font-weight: bold;
                }
                .header { 
                    background: linear-gradient(135deg, #007bff, #0056b3); 
                    color: white; 
                    padding: 30px 20px; 
                    text-align: center; 
                }
                .header h1 {
                    margin: 0;
                    font-size: 28px;
                    font-weight: 300;
                }
                .content { 
                    padding: 40px 30px; 
                    background: #ffffff;
                }
                .content h2 {
                    color: #007bff;
                    margin-top: 0;
                    font-size: 24px;
                    font-weight: 400;
                }
                .invitation-details {
                    background: #f8f9fa;
                    padding: 20px;
                    border-left: 4px solid #007bff;
                    margin: 20px 0;
                    border-radius: 4px;
                }
                .button { 
                    display: inline-block; 
                    padding: 15px 30px; 
                    background: linear-gradient(135deg, #007bff, #0056b3); 
                    color: white !important; 
                    text-decoration: none; 
                    border-radius: 25px; 
                    font-weight: bold;
                    font-size: 16px;
                    box-shadow: 0 2px 4px rgba(0, 123, 255, 0.3);
                }
                .debug-info {
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 5px;
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                }
                .footer { 
                    padding: 30px 20px; 
                    text-align: center; 
                    color: #666; 
                    font-size: 14px; 
                    background: #f8f9fa;
                    border-top: 1px solid #dee2e6;
                }
                @media (max-width: 600px) {
                    .container { margin: 10px; }
                    .content { padding: 20px; }
                    .header { padding: 20px; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="test-banner">
                    🧪 TEST EMAIL - ETHEREAL EMAIL - NO REAL EMAIL SENT 🧪
                </div>
                <div class="header">
                    <h1>Welcome to {{ company_name }}</h1>
                </div>
                <div class="content">
                    <h2>🎉 You've been invited!</h2>
                    <p>Great news! You have been invited to join <strong>{{ company_name }}</strong> as a <strong>{{ role }}</strong>.</p>
                    
                    <div class="invitation-details">
                        <p><strong>📧 Email:</strong> {{ recipient_email }}</p>
                        <p><strong>👤 Role:</strong> {{ role }}</p>
                        <p><strong>⏰ Expires:</strong> {{ expiry_date }}</p>
                    </div>
                    
                    <p>Click the button below to accept your invitation and set up your account:</p>
                    
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{{ invitation_url }}" class="button">Accept Invitation</a>
                    </p>
                    
                    <p><strong>⚠️ Important:</strong> This invitation will expire in 7 days.</p>
                    <p>If you have any questions, please contact your administrator.</p>
                    
                    <div class="debug-info">
                        <strong>🔧 DEBUG INFO (Ethereal Email Testing):</strong><br>
                        Token: {{ token }}<br>
                        Generated: {{ current_date }}<br>
                        Provider: {{ provider }}<br>
                        View Email: <a href="{{ view_url }}" target="_blank">{{ view_url }}</a>
                    </div>
                </div>
                <div class="footer">
                    <p>This invitation was sent from <strong>{{ company_name }}</strong></p>
                    <p>If you didn't expect this invitation, you can safely ignore this email.</p>
                    <p style="margin-top: 20px; font-size: 12px; color: #28a745;">
                        📧 Sent via Ethereal Email (Development Only) | 
                        🔗 <a href="{{ view_url }}">View All Test Messages</a>
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

    async def _send_via_smtp(self, message):
        """Send email via SMTP with provider-specific configurations"""
        smtp_config = {
            "hostname": settings.smtp_host,
            "port": settings.smtp_port,
        }

        # Add TLS if specified
        if hasattr(settings, "smtp_use_tls") and settings.smtp_use_tls:
            smtp_config["start_tls"] = True

        # Add authentication if provided
        if hasattr(settings, "smtp_username") and settings.smtp_username:
            smtp_config.update(
                {
                    "username": settings.smtp_username,
                    "password": settings.smtp_password,
                }
            )

        await aiosmtplib.send(message, **smtp_config)

    # ... Rest of your existing methods remain the same ...

    async def verify_invitation_token(self, token: str) -> Optional[dict]:
        """Verify and return invitation data"""
        invitation = await self.invitations_collection.find_one(
            {"token": token, "used": False, "expires_at": {"$gt": datetime.utcnow()}}
        )

        return invitation

    async def mark_invitation_as_used(self, token: str):
        """Mark invitation as used"""
        await self.invitations_collection.update_one(
            {"token": token}, {"$set": {"used": True, "used_at": datetime.utcnow()}}
        )

    async def get_pending_invitations(self) -> list[dict]:
        """Get all pending invitations"""
        cursor = self.invitations_collection.find(
            {"used": False, "expires_at": {"$gt": datetime.utcnow()}}
        )

        return await cursor.to_list(None)

    async def cancel_invitation(self, token: str) -> bool:
        """Cancel an invitation"""
        result = await self.invitations_collection.delete_one({"token": token})
        return result.deleted_count > 0

    async def test_connection(self) -> bool:
        """Test SMTP connection"""
        try:
            smtp_config = {
                "hostname": settings.smtp_host,
                "port": settings.smtp_port,
            }

            if hasattr(settings, "smtp_use_tls") and settings.smtp_use_tls:
                smtp_config["start_tls"] = True

            if hasattr(settings, "smtp_username") and settings.smtp_username:
                smtp_config.update(
                    {
                        "username": settings.smtp_username,
                        "password": settings.smtp_password,
                    }
                )

            smtp = aiosmtplib.SMTP(**smtp_config)
            await smtp.connect()
            if smtp_config.get("username"):
                await smtp.login(smtp_config["username"], smtp_config["password"])
            await smtp.quit()

            print(f"✅ {self.email_provider.title()} connection successful!")
            if self.email_provider == "ethereal":
                print(f"🔗 View messages at: https://ethereal.email/messages")
            return True

        except Exception as e:
            print(f"❌ {self.email_provider.title()} connection failed: {e}")
            return False

    def get_provider_info(self) -> dict:
        """Get information about current email provider"""
        provider_info = {
            "provider": self.email_provider,
            "host": getattr(settings, "smtp_host", "Not configured"),
            "port": getattr(settings, "smtp_port", "Not configured"),
            "username": getattr(settings, "smtp_username", "Not configured"),
            "from_email": getattr(settings, "smtp_from_email", "Not configured"),
        }

        if self.email_provider == "ethereal":
            provider_info["view_url"] = "https://ethereal.email/messages"
            provider_info["note"] = "Development only - emails are not actually sent"
        elif self.email_provider == "gmail":
            provider_info["note"] = (
                "Make sure to use App Password, not regular password"
            )

        return provider_info
