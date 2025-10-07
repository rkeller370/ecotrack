async function changeIP(ip) {
  console.log(ip)
  let location = "";
  if (ip) {
    try {
      const response = await fetch(`https://ipapi.co/${ip}/json/`);
      const data = await response.json();
      console.log(data)
      location = `${data.city}, ${data.region}, ${data.country_name}`;
    } catch (err) {
      console.error("Error fetching location:", err);
      location = "Unknown";
    }
  }

  return location;
}

module.exports = { changeIP };
