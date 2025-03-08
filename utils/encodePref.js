function encodeUserPreferences(formData) {
    const vector = [];
  
    const oneHot = (value, options) =>
      options.map((opt) => (opt === value ? 1 : 0));
  
    // Use provided value or a default string for one-hot encoding
    vector.push(
      ...oneHot(formData.location || "no-preference", [
        "northeast",
        "south",
        "midwest",
        "west",
      ])
    );
  
    // Using 'type' as the college type field
    vector.push(
      ...oneHot(formData.type || "no-preference", ["public", "private", "both"])
    );
  
    // Ordinal mapping for the rest of the preferences
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
      low: 1,
      abundant: 3,
      few: 1,
    };
  
    // Helper to safely get ordinal value with a fallback default of 0
    const getOrdinal = (value) => {
      const v = ordinalMap[value];
      return v !== undefined ? v / 3 : 0;
    };
  
    // Map allowed fields to the corresponding ordinal preferences
    // Here we assume:
    // - goodMajor corresponds to major importance
    // - tuition corresponds to budget
    // - rigor corresponds to academic rigor
    // - jobOpp corresponds to internships (or job opportunities)
    // - abroad corresponds to study abroad
    vector.push(
      getOrdinal(formData.goodMajor),
      getOrdinal(formData.tuition),
      getOrdinal(formData.athletics),
      getOrdinal(formData.rigor),
      getOrdinal(formData.diversity),
      getOrdinal(formData.jobOpp),
      getOrdinal(formData.abroad)
    );
  
    // One-hot encode the remaining categorical fields.
    vector.push(
      ...oneHot(formData.housing || "no-preference", [
        "on-campus",
        "off-campus",
        "no-preference",
      ])
    );
    vector.push(
      ...oneHot(formData.climate || "no-preference", [
        "warm",
        "cold",
        "moderate",
        "no-preference",
      ])
    );
    vector.push(
      ...oneHot(formData.socialLife || "balanced", ["active", "quiet", "balanced"])
    );
    vector.push(
      ...oneHot(formData.size || "no-preference", [
        "small",
        "medium",
        "large",
        "no-preference",
      ])
    );
  
    // If a GPA is provided, include it; otherwise, skip.
    if (typeof formData.gpa === "number") {
      const maxGPA = 5.0;
      vector.push(formData.gpa / maxGPA);
    }
  
    // Calculate the norm, then normalize the vector.
    const norm = Math.sqrt(vector.reduce((sum, val) => sum + val * val, 0));
    return norm ? vector.map((v) => v / norm) : vector;
  }
  
  module.exports = { encodeUserPreferences };  