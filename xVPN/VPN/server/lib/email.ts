let nodemailer: any;
let transporter: any;

try {
  nodemailer = require("nodemailer");
  // Create email transporter using Gmail SMTP
  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
} catch (error) {
  console.warn("nodemailer module not found. Email functionality will be disabled.");
}

/**
 * Sends email verification link to user
 */
export async function sendVerificationEmail(
  email: string,
  username: string,
  verificationToken: string,
  baseUrl: string
): Promise<boolean> {
  try {
    const verificationUrl = `${baseUrl}/verify-email?token=${verificationToken}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify your xVPN Account",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
            <h1 style="color: white; margin: 0;">xVPN Account Verification</h1>
          </div>
          <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px;">
            <p style="color: #333; font-size: 16px;">
              Hello <strong>${username}</strong>,
            </p>
            <p style="color: #666; font-size: 14px; line-height: 1.6;">
              Thank you for signing up for xVPN! To complete your account setup and access our premium VPN services, please verify your email address by clicking the button below.
            </p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${verificationUrl}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; padding: 12px 30px; border-radius: 4px; font-weight: bold;">
                Verify Email Address
              </a>
            </div>
            <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px;">
              Or copy and paste this link in your browser:<br/>
              <code style="color: #667eea; word-break: break-all;">${verificationUrl}</code>
            </p>
            <p style="color: #999; font-size: 12px; text-align: center; margin-top: 20px;">
              This link will expire in 24 hours.
            </p>
            <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
              If you did not sign up for xVPN, please ignore this email.<br/>
              © 2024 xVPN. All rights reserved.
            </p>
          </div>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
    return true;
  } catch (error) {
    console.error("Error sending verification email:", error);
    return false;
  }
}

/**
 * Sends password reset email to user
 */
export async function sendPasswordResetEmail(
  email: string,
  username: string,
  resetToken: string,
  baseUrl: string
): Promise<boolean> {
  try {
    const resetUrl = `${baseUrl}/reset-password?token=${resetToken}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Reset Your xVPN Password",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
            <h1 style="color: white; margin: 0;">xVPN Password Reset</h1>
          </div>
          <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px;">
            <p style="color: #333; font-size: 16px;">
              Hello <strong>${username}</strong>,
            </p>
            <p style="color: #666; font-size: 14px; line-height: 1.6;">
              We received a request to reset your xVPN account password. Click the button below to create a new password.
            </p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetUrl}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; padding: 12px 30px; border-radius: 4px; font-weight: bold;">
                Reset Password
              </a>
            </div>
            <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px;">
              This link will expire in 1 hour.
            </p>
            <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
              If you did not request a password reset, you can safely ignore this email.<br/>
              © 2024 xVPN. All rights reserved.
            </p>
          </div>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Password reset email sent to ${email}`);
    return true;
  } catch (error) {
    console.error("Error sending password reset email:", error);
    return false;
  }
}
