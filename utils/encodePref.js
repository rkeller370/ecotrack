function encodeUserPreferences(formData) {
  const vector = [];

  const oneHot = (value, options) =>
    options.map((opt) => (opt === value ? 1 : 0));

  vector.push(
    ...oneHot(formData.location, ["northeast", "south", "midwest", "west"])
  );

  vector.push(...oneHot(formData.collegeType, ["public", "private", "both"]));

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
  vector.push(
    ordinalMap[formData.majorImportance] / 3,
    ordinalMap[formData.budget] / 3,
    ordinalMap[formData.athletics] / 3,
    ordinalMap[formData.academicRigor] / 3,
    ordinalMap[formData.diversity] / 3,
    ordinalMap[formData.internships] / 3,
    ordinalMap[formData.studyAbroad] / 3
  );

  vector.push(
    ...oneHot(formData.housing, ["on-campus", "off-campus", "no-preference"])
  );
  vector.push(
    ...oneHot(formData.climate, ["warm", "cold", "moderate", "no-preference"])
  );
  vector.push(...oneHot(formData.socialLife, ["active", "quiet", "balanced"]));
  vector.push(
    ...oneHot(formData.campusSize, [
      "small",
      "medium",
      "large",
      "no-preference",
    ])
  );

  const maxGPA = 5.0;
  vector.push(formData.gpa / maxGPA)

  const norm = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));
  return vector.map((v) => v / norm);
}

module.exports = { encodeUserPreferences };
