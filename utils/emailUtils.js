const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

const sendVerifEmail = async (email, subject, html, token) => {
  const mailOptions = {
    from: process.env.GMAIL_USER,
    to: email,
    subject,
    html,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (err) {
    console.error("Error sending email:", err);
  }
};

const sendLockoutEmail = async (email, ip, lockDuration) => {
  const mailOptions = {
    from: process.env.GMAIL_USER,
    to: email,
    subject: 'Account Locked - Security Alert',
    html: `Your account has been locked due to multiple failed login attempts.`,
  };

  await transporter.sendMail(mailOptions);
};

module.exports = { sendVerifEmail, sendLockoutEmail };