const fs = require("fs");

const universities = require("../info/colleges.json");

function encodeUniversityAttributes(university) {
  const vector = [];

  const oneHot = (value, options) =>
    options.map((opt) => (opt === value ? 1 : 0));

  vector.push(
    ...oneHot(university.location, ["northeast", "south", "midwest", "west"])
  );

  vector.push(...oneHot(university.type, ["public", "private", "both"]));

  const ordinalMap = {
    "very-important": 3,
    important: 2,
    "not-important": 1,
    "no-preference": 0,
    elite: 3,
    good: 2,
    average: 1,
    "highly-competitive": 3,
    moderate: 2,
    casual: 1,
    high: 3,
    moderate: 2,
    low: 1,
    abundant: 3,
    moderate: 2,
    few: 1,
    important: 2,
    moderate: 1,
    "not-important": 0,
  };

  // Adding default values when data is missing
  const safeGetOrdinal = (value) => ordinalMap[value] || 0;

  vector.push(
    safeGetOrdinal(university.academicRigor) / 3,
    safeGetOrdinal(university.athletics) / 3,
    safeGetOrdinal(university.diversity) / 3,
    safeGetOrdinal(university.internships) / 3,
    safeGetOrdinal(university.studyAbroad) / 3
  );

  vector.push(
    ...oneHot(university.housing, ["on-campus", "off-campus", "no-preference"])
  );
  vector.push(
    ...oneHot(university.climate, ["warm", "cold", "moderate", "no-preference"])
  );
  vector.push(
    ...oneHot(university.socialLife, ["active", "quiet", "balanced"])
  );
  vector.push(
    ...oneHot(university.campusSize, [
      "small",
      "medium",
      "large",
      "no-preference",
    ])
  );

  const maxGPA = 5.0;
  vector.push(university.gpa / maxGPA);

  const norm = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));
  return vector.map((v) => v / norm);
}

function initialize() {
  const universitiesWithVectors = universities.map((uni) => ({
    ...uni,
    normalizedVector: encodeUniversityAttributes(uni),
  }));

  fs.writeFileSync(
    "./info/colleges.json",
    JSON.stringify(universitiesWithVectors, null, 2)
  );

  return universitiesWithVectors;
}

module.exports = { initalize };