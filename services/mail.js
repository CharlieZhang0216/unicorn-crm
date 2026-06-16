/**
 * Email Service for Unicorn CRM
 * Uses nodemailer with SMTP config from .env
 * Falls back to console output (stdout) for development/testing
 */

const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

// Load .env
let envConfig = {};
try {
  const envPath = path.join(__dirname, '..', '.env');
  if (fs.existsSync(envPath)) {
    const content = fs.readFileSync(envPath, 'utf8');
    content.split('\n').forEach(line => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        const eqIndex = trimmed.indexOf('=');
        if (eqIndex > 0) {
          envConfig[trimmed.substring(0, eqIndex).trim()] = trimmed.substring(eqIndex + 1).trim();
        }
      }
    });
  }
} catch (e) {
  // .env not found, use defaults
}

const SMTP_CONFIG = {
  host: envConfig.SMTP_HOST || process.env.SMTP_HOST,
  port: parseInt(envConfig.SMTP_PORT || process.env.SMTP_PORT || '587'),
  secure: (envConfig.SMTP_SECURE || process.env.SMTP_SECURE) === 'true',
  auth: {
    user: envConfig.SMTP_USER || process.env.SMTP_USER,
    pass: envConfig.SMTP_PASSWORD || process.env.SMTP_PASSWORD
  }
};

const FROM_ADDRESS = envConfig.SMTP_FROM || process.env.SMTP_FROM || 'noreply@unicorn-crm.com';
const BASE_URL = envConfig.BASE_URL || process.env.BASE_URL || 'http://localhost:3000';

// Determine if we have valid SMTP config
const hasSmtpConfig = SMTP_CONFIG.host && SMTP_CONFIG.auth.user && SMTP_CONFIG.auth.pass;

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  if (hasSmtpConfig) {
    transporter = nodemailer.createTransport(SMTP_CONFIG);
  } else {
    // Console mode — log emails to stdout instead of sending
    transporter = {
      sendMail: async (mailOptions) => {
        console.log('\n' + '='.repeat(60));
        console.log('[MAIL SERVICE] Email (console mode — SMTP not configured)');
        console.log('='.repeat(60));
        console.log('From:', mailOptions.from);
        console.log('To:', mailOptions.to);
        console.log('Subject:', mailOptions.subject);
        console.log('--- Body ---');
        console.log(mailOptions.html || mailOptions.text);
        console.log('='.repeat(60) + '\n');
        return { messageId: `console-${Date.now()}`, accepted: [mailOptions.to], response: 'console' };
      }
    };
  }
  return transporter;
}

/**
 * Send verification email after registration
 * @param {object} user - { id, email, full_name }
 * @param {string} token - Verification token
 */
async function sendVerificationEmail(user, token) {
  const verifyUrl = `${BASE_URL}/auth/verify/${token}`;
  const htmlBody = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #1a56db;">Unicorn CRM</h2>
      <p>Hi ${user.full_name || user.username},</p>
      <p>Thank you for creating an account at Unicorn CRM. Please verify your email address by clicking the button below:</p>
      <p style="text-align: center; margin: 30px 0;">
        <a href="${verifyUrl}" style="background-color: #1a56db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify Email Address</a>
      </p>
      <p>Or copy and paste this link into your browser:</p>
      <p style="word-break: break-all; color: #666;">${verifyUrl}</p>
      <p>This link will expire in 24 hours.</p>
      <p>If you did not create this account, please ignore this email.</p>
      <hr style="border: 1px solid #eee; margin: 20px 0;">
      <p style="color: #999; font-size: 12px;">Unicorn CRM — Enterprise Customer Relationship Management</p>
    </div>
  `;

  return getTransporter().sendMail({
    from: FROM_ADDRESS,
    to: user.email,
    subject: 'Verify your email address — Unicorn CRM',
    html: htmlBody
  });
}

/**
 * Send password reset email
 * @param {object} user - { id, email, full_name }
 * @param {string} token - Reset token
 */
async function sendPasswordReset(user, token) {
  const resetUrl = `${BASE_URL}/auth/reset-password?token=${token}`;
  const htmlBody = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #1a56db;">Unicorn CRM</h2>
      <p>Hi ${user.full_name || user.username},</p>
      <p>You (or someone) requested a password reset for your Unicorn CRM account. Click the button below to set a new password:</p>
      <p style="text-align: center; margin: 30px 0;">
        <a href="${resetUrl}" style="background-color: #1a56db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a>
      </p>
      <p>Or copy and paste this link into your browser:</p>
      <p style="word-break: break-all; color: #666;">${resetUrl}</p>
      <p>This link will expire in 1 hour.</p>
      <p>If you did not request this reset, please ignore this email.</p>
      <hr style="border: 1px solid #eee; margin: 20px 0;">
      <p style="color: #999; font-size: 12px;">Unicorn CRM — Enterprise Customer Relationship Management</p>
    </div>
  `;

  return getTransporter().sendMail({
    from: FROM_ADDRESS,
    to: user.email,
    subject: 'Password Reset Request — Unicorn CRM',
    html: htmlBody
  });
}

/**
 * Send a general notification email
 * @param {object} user - { email, full_name }
 * @param {string} subject - Email subject
 * @param {string} body - HTML body content
 */
async function sendNotification(user, subject, body) {
  const htmlBody = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #1a56db;">Unicorn CRM</h2>
      <p>Hi ${user.full_name || 'there'},</p>
      <div>${body}</div>
      <hr style="border: 1px solid #eee; margin: 20px 0;">
      <p style="color: #999; font-size: 12px;">Unicorn CRM — Enterprise Customer Relationship Management</p>
    </div>
  `;

  return getTransporter().sendMail({
    from: FROM_ADDRESS,
    to: user.email,
    subject: subject,
    html: htmlBody
  });
}

module.exports = {
  sendVerificationEmail,
  sendPasswordReset,
  sendNotification,
  hasSmtpConfig
};
