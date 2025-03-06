const nodemailer = require("nodemailer");

const url = "https://creative-horse-1afc49.netlify.app";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "donotreply.mshstutoring@gmail.com",
    pass: process.env.GMAIL_PASS,
  },
});

const sendVerifEmail = async (email, subject, html, token) => {
  const mailOptions = {
    from: "donotreply.mshstutoring@gmail.com",
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
  let location = "";
  if (ip) {
    try {
      const response = await fetch(`https://ipapi.co/${ip}/json/`);
      const data = await response.json();
      location = `${data.city}, ${data.region}, ${data.country_name}`;
    } catch (err) {
      console.error("Error fetching location:", err);
      location = "Unknown";
    }
  }

  const mailOptions = {
    from: "donotreply.mshstutoring@gmail.com",
    to: email,
    subject: "Account Locked - Security Alert",
    html: `<!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap" rel="stylesheet">
        <style>
        * {
        font-family: 'Inter', sans-serif;
        }
          body {
            font-family: 'Inter', sans-serif;
            background-color: #f5f5f5;
            color: #333333;
            margin: 0;
            padding: 0;
          }
          .email-container {
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
          }
          .email-header {
            background-color: #4caf50;
            color: white;
            padding: 24px 20px;
            text-align: center;
            font-size: 1.5rem;
            font-weight: 700;
          }
          .email-body {
            padding: 30px;
            text-align: center;
          }
          .email-body p {
            font-size: 1rem;
            margin-bottom: 24px;
            line-height: 1.5;
            color: #666666;
          }
          .email-body ul {
            list-style: none;
            padding: 0;
            margin: 20px auto;
            max-width: 300px;
            text-align: left;
          }
          .email-body li {
            margin-bottom: 12px;
            padding: 8px 0;
            border-bottom: 1px solid #eeeeee;
          }
          .email-body li:last-child {
            border-bottom: none;
          }
          .email-body strong {
            color: #333333;
          }
          .email-body a {
            color: #4caf50;
            text-decoration: none;
            font-weight: 500;
            display: inline-block;
            margin-top: 16px;
          }
          .email-footer {
            background-color: #212121;
            color: white;
            padding: 24px 20px;
            text-align: center;
            font-size: 0.875rem;
            line-height: 1.6;
          }
          .email-footer a {
            color: #4caf50;
            text-decoration: none;
            font-weight: 500;
            margin: 0 8px;
          }
          .email-footer a:hover {
            color: #3e8e41;
            text-decoration: underline;
          }
        </style>
      </head>
      <body style="font-family: 'Inter', sans-serif;">
        <div class="email-container">
          <div class="email-header">
            Security Alert
          </div>
          <div class="email-body">
            <p>Your account has been temporarily locked due to 3 failed login attempts.</p>
            <p><strong>Details:</strong></p>
            <ul>
              <li>Time: ${new Date().toLocaleString()}</li>
              <li>IP Address: ${ip} (${location})</li>
              <li>Lock Duration: ${Math.round(
                lockDuration / 60000
              )} minutes</li>
            </ul>
            <p>If this was you, please wait until the lock expires to try again.</p>
            <p>If this wasn't you, please contact our security team immediately.</p>
            <p><a href="${url}/security">Review Account Security</a></p>
          </div>
          <div class="email-footer">
            © AdmitVault 2024. All rights reserved.<br>
            <a href="${url}">Visit our website</a> | 
            <a href="${url}/privacy">Privacy Policy</a> | 
            <a href="${url}/terms">Terms of Service</a>
          </div>
        </div>
      </body>
    </html>`,
  };

  await transporter.sendMail(mailOptions);
};

module.exports = { sendVerifEmail, sendLockoutEmail };
