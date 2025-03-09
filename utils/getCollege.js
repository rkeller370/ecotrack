const axios = require("axios");

const collegeDataCache = new Map();
const CACHE_EXPIRATION_MS = 24 * 60 * 60 * 1000;

async function getCachedCollegeData(collegeName) {
  const cacheEntry = collegeDataCache.get(collegeName);
  if (cacheEntry && Date.now() - cacheEntry.timestamp < CACHE_EXPIRATION_MS) {
    return cacheEntry.data;
  }

  const freshData = await fetchCollegeDataFromAPI(collegeName);
  collegeDataCache.set(collegeName, { data: freshData, timestamp: Date.now() });
  return freshData;
}

async function fetchCollegeDataFromAPI(collegeName) {
  try {
    const apiKey = process.env.GOV_API_KEY;
    const apiUrl = `https://api.data.gov/ed/collegescorecard/v1/schools?school.name=${encodeURIComponent(
      collegeName
    )}&api_key=${apiKey}&_fields=school.name,school.city,school.state,admissions.admission_rate.overall,cost.tuition.in_state`;

    const response = await axios.get(apiUrl);
    const results = response.data.results;
    let acceptanceRate, tuition, city, state, location, collegeSize;

    if (results && results.length > 0) {
      const schoolData = results[0];
      acceptanceRate = schoolData.admissions?.admission_rate?.overall;
      tuition = schoolData.cost?.tuition?.in_state;
      city = schoolData.school?.city;
      state = schoolData.school?.state;
      location = city && state ? `${city}, ${state}` : "";
      studentSize = schoolData.latest?.student?.size || "N/A";
    }

    const headerImage = await fetchWikipediaImage(collegeName);

    return {
      header: `${collegeName} at a Glance`,
      description: `${collegeName} is renowned for its academic excellence and vibrant campus community.`,
      acceptanceRate: acceptanceRate
        ? (acceptanceRate * 100).toFixed(2) + "%"
        : "N/A",
      location: location,
      tuition: tuition || "N/A",
      headerImage: headerImage,
    };
  } catch (error) {
    console.error(`Error fetching data for ${collegeName}:`, error);
  }
  return {};
}

async function fetchWikipediaImage(collegeName) {
  try {
    const wikiSearchUrl = `https://en.wikipedia.org/w/api.php?action=query&format=json&titles=${encodeURIComponent(
      collegeName
    )}&prop=pageimages&pithumbsize=800`;
    const response = await axios.get(wikiSearchUrl);
    const pages = response.data.query.pages;

    for (const pageId in pages) {
      if (pages[pageId].thumbnail) {
        return pages[pageId].thumbnail.source;
      }
    }
  } catch (error) {
    console.error(`Error fetching Wikipedia image for ${collegeName}:`, error);
  }
  return "https://via.placeholder.com/800x400?text=No+Image+Available";
}

async function getCollegeData(collegeName) {
  const rawData = fs.readFileSync("./info/collegeInfo.json", "utf-8");
  const universities = JSON.parse(rawData).filter(
    (uni) => uni.name === collegeName
  );
  if (universities.length > 0) {
    return universities[0];
  }
  return await getCachedCollegeData(collegeName);
}

module.exports = { getCachedCollegeData, getCollegeData };
