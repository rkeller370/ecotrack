const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  };
  
  const validatePassword = (password, email, previousPasswords = []) => {
    const minLength = 10; // Increased minimum length
    const hasUpperCase = /[A-Z]/;
    const hasLowerCase = /[a-z]/;
    const hasNumbers = /\d/;
    const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/;
  
    // Basic checks
    if (password.length < minLength) {
      return {
        valid: false,
        message: `Password must be at least ${minLength} characters long`,
      };
    }
  
    if (!hasUpperCase.test(password)) {
      return {
        valid: false,
        message: "Password must contain at least one uppercase letter",
      };
    }
  
    if (!hasLowerCase.test(password)) {
      return {
        valid: false,
        message: "Password must contain at least one lowercase letter",
      };
    }
  
    if (!hasNumbers.test(password)) {
      return {
        valid: false,
        message: "Password must contain at least one number",
      };
    }
  
    if (!hasSpecialChars.test(password)) {
      return {
        valid: false,
        message: "Password must contain at least one special character",
      };
    }
  
    // Check for common weak passwords
    const commonPasswords = [
      "123456",
      "password",
      "12345678",
      "qwerty",
      "123456789",
      "12345",
      "1234",
      "111111",
      "1234567",
      "dragon",
      "123123",
      "baseball",
      "abc123",
      "football",
      "monkey",
      "letmein",
      "shadow",
      "master",
      "666666",
      "qwertyuiop",
      "123321",
      "mustang",
      "1234567890",
      "michael",
      "654321",
      "superman",
      "1qaz2wsx",
      "7777777",
      "qazwsx",
      "password1",
      "qwerty123",
      "welcome",
      "iloveyou",
      "adobe123",
      "admin",
      "login",
      "passw0rd",
      "starwars",
      "zaq1zaq1",
      "zaq12wsx",
      "123qwe",
      "access",
      "flower",
      "cheese",
      "computer",
      "freedom",
      "whatever",
      "princess",
      "q1w2e3r4",
      "secret",
      "charlie",
      "hottie",
      "loveme",
      "sunshine",
      "ashley",
      "bailey",
      "jordan",
      "mercedes",
      "austin",
      "harley",
      "maggie",
      "buster",
      "jennifer",
      "nicole",
      "justin",
      "tigger",
      "soccer",
      "ginger",
      "cookie",
      "pepper",
      "cameron",
      "scooter",
      "joshua",
      "lovely",
      "matthew",
      "killer",
      "jasmine",
      "samantha",
      "donald",
      "iloveu",
      "snoopy",
      "sweet",
      "eagle",
      "samsung",
      "qwert",
      "11111111",
      "12345678910",
      "000000",
      "987654321",
      "888888",
      "999999",
      "101010",
      "121212",
      "131313",
      "159753",
      "159357",
      "123654",
      "777777",
      "147258",
      "852963",
      "456456",
      "00000000",
      "999999999"
    ];  
    if (commonPasswords.includes(password.toLowerCase())) {
      return {
        valid: false,
        message: "Password is too common and easily guessable",
      };
    }
  
    // Check for email or username in password
    const emailParts = email.split("@")[0].split(/[.\-_]/); // Split email local part
    if (
      emailParts.some((part) => password.toLowerCase().includes(part.toLowerCase()))
    ) {
      return {
        valid: false,
        message: "Password should not contain your email or username",
      };
    }
  
    // Check for password reuse
    if (previousPasswords.length > 0) {
      const isReused = previousPasswords.some((prevPassword) =>
        bcrypt.compareSync(password, prevPassword)
      );
      if (isReused) {
        return {
          valid: false,
          message: "Password has been used before. Please choose a new one.",
        };
      }
    }
  
    // Check for sequential or repeated characters
    if (/(.)\1{2,}/.test(password)) {
      return {
        valid: false,
        message: "Password contains repeated characters",
      };
    }
  
    if (/123|234|345|456|567|678|789|890/.test(password)) {
      return {
        valid: false,
        message: "Password contains sequential characters",
      };
    }
  
    return { valid: true, message: "Password is valid" };
  };
  
  module.exports = { validateEmail, validatePassword };