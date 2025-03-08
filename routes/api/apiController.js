const { getDb, initializeMongo } = require("../../config/db");
const { sanitizeInput, sanitizeEssayInput } = require("../../utils/sanitize");
const { encodeUserPreferences } = require("../../utils/encodePref");
const { initialize } = require("../../utils/encodeCollege");
const { getCachedCollegeData } = require("../../utils/getCollege");
const { OpenAI } = require("openai");
const axios = require("axios");
const fs = require("fs");
const faiss = require("faiss-node");

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

const initializeDatabase = async () => {
  db = await getDb();
};

let index = null;

async function initializeFAISS() {
  await initialize();
}

initializeFAISS()

const url = "https://creative-horse-1afc49.netlify.app";

initializeDatabase();

exports.getUniversities = async (req, res) => {
  try {
    const { college } = req.query;

    if (!college || !String(college) || college.trim() === "") {
      return res.status(400).json({
        success: false,
        message: "No college provided",
      });
    }

    const govApiKey = process.env.GOV_API_KEY;
    const response = await axios.get(
      `https://api.data.gov/ed/collegescorecard/v1/schools.json`,
      {
        params: {
          api_key: govApiKey,
          "school.name": college,
          per_page: 10,
        },
      }
    );

    const universities = response.data.results.map((uni) => ({
      name: uni.school.name,
      city: uni.school.city,
      state: uni.school.state,
    }));

    return res.json({
      success: true,
      results: universities,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "An error occurred while fetching university data",
    });
  }
};

exports.evaluateStudent = async (req, res) => {
  if (!db) {
    db = getDb();
  }
  try {
    const studentData = req.body;
    const user = await db.collection("users").findOne({ userId: req.user });

    if (!studentData) {
      return res.status(400).json({
        success: false,
        message: "No student data provided",
      });
    }

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (user.recommended) {
      return res.status(400).json({
        success: false,
        message: "User already recommended",
      });
    }

    const allowedFields = [
      "gpa",
      "major",
      "gradeLevel",
      "classRank",
      "currentCourses",
      "studyHours",
      "studyMethods",
      "strengths",
      "weaknesses",
      "extracurriculars",
      "targetSchool",
      "testsTaken",
      "testScores",
      "skills",
      "awards",
    ];

    const validatedData = {};

    for (const field of allowedFields) {
      if (studentData[field] !== undefined) {
        validatedData[field] = sanitizeInput(
          studentData[field],
          field == "extracurriculars" ? 700 : 200
        );
      }
    }

    await db
      .collection("users")
      .updateOne({ userId: req.user }, { $set: { inputtedValues: validatedData } });

    const prompt = `You are an elite AI-powered college admissions consultant, specializing in meticulously analyzing high school student applications. Your mission is to deliver an extraordinarily detailed evaluation, packed with precise, high-value recommendations that dramatically increase the student’s admission chances at their target colleges.

      You must:
      - **Tailor all feedback** to the student’s data and the unique priorities of their target colleges (based on Common Data Set (CDS), mission statements, and admissions trends).
      - **Be hyper-specific** by comparing the student's profile against competitive benchmarks (e.g., middle 50% ranges for GPA, SAT/ACT, course rigor, extracurricular expectations).
      - **Provide a vast number of insights**—not just 3-4, but **multiple, highly detailed, strategic** recommendations per section.
      - **Prioritize actionable strategies**—every recommendation must be measurable, concrete, and immediately implementable.
      
      ---
      
      ### **Structured Input:**
      \`\`\`json
      ${JSON.stringify(validatedData, null, 2)}
      \`\`\`
      
      ---
      
      ### **Deliverables:**
      You must generate a JSON object that contains **four comprehensive sections**:  
      
      #### **1. Holistic Portfolio Assessment**
      - Assign an overall **portfolio rating** ('Exceptional', 'Very Strong', 'Strong', 'Good', 'Fair', 'Needs Improvement') based on the student’s profile.
      - Justify this rating by analyzing the student’s strengths, weaknesses, and alignment with their college goals.
      - **Summarize unique strengths** that set the student apart, connecting them to the priorities of their target colleges.
      
      #### **2. In-Depth Analysis of Key Areas**
      For **each** category below, provide **at least 6-8 highly detailed** recommendations tailored to the student's strengths, weaknesses, and target colleges.
      
      - **Academics:**
        - Evaluate **GPA, course rigor, trends, and standardized test scores** compared to CDS data.
        - **Identify inconsistencies or areas for improvement.**
        - Provide **specific, multi-step recommendations** for academic enhancement.
        - **Examples of strong recommendations:**
          - “Enroll in AP Chemistry and AP Calculus BC next year, as [Target College] reports 92% of admitted students taking both.”
          - “Increase SAT Math score from 710 to 770 to meet [Target College’s] middle 50% range (750-790).”
      
      - **Extracurriculars:**
        - Assess **leadership, impact, depth of involvement, and initiative.**
        - **Recommend at least 6-8 strategic moves** to enhance extracurricular strength.
        - **Examples of strong recommendations:**
          - “Launch a self-led research project on AI in healthcare and submit findings to the Regeneron Science Talent Search.”
          - “Expand [volunteering initiative] by partnering with [organization] to reach 500+ people annually.”
          - “Compete in the USA Biology Olympiad to gain national-level recognition.”
      
      - **Awards & Recognition:**
        - **Analyze the competitiveness** of current awards.
        - Suggest **at least 5-6 new high-profile awards or competitions.**
        - **Examples of strong recommendations:**
          - “Apply for the Davidson Fellows Scholarship ($50,000) for your work in [field].”
          - “Compete in the Conrad Challenge to gain entrepreneurial recognition.”
      
      - **Scholarships:**
        - Identify **specific, high-value scholarships** based on the student’s profile.
        - Provide **at least 5-6 opportunities with clear justification**.
        - **Examples of strong recommendations:**
          - “Apply for the Coca-Cola Scholars Program ($20,000) given your leadership in [activity].”
          - “Submit your STEM research to the Intel Science and Engineering Fair for scholarship opportunities.”
      
      #### **3. Targeted Improvement Recommendations**
      For **each** of the following, provide **at least 6-8 concrete, strategic recommendations** tailored to the student’s situation:
      
      - **Academics**
      - **Extracurriculars**
      - **Essays**
      - **Time Management**
      - **College List Optimization**
      
      Each recommendation must be **highly detailed and actionable**, such as:
      - “Reduce extracurricular overload by prioritizing [top 3 activities] and cutting [least impactful one].”
      - “Structure personal statement around a ‘challenge-growth-impact’ framework to enhance narrative flow.”
      
      #### **4. College List Evaluation & Expansion**
      - **Assess the competitiveness** of the student’s college list.
      - Provide **at least 4-5 additional schools** tailored to the student's profile.
      - Justify each new school based on **program strength, financial aid, admissions probability, and alignment with the student’s goals.**
      - **Example recommendations:**
        - “Consider applying to [Highly Competitive College] because of its [specialized program], where [X%] of students pursue [intended major].”
        - “Add [Safety School] to your list, as it offers strong merit aid and has a [X%] admissions rate.”
      
      ---
      
      ### **Output Format**
      Return a **pure JSON response** (NO code blocks, NO formatting, NO extra text). The JSON must be **deeply structured** for seamless integration into a frontend UI.
      
      \`\`\`json
      {
        "portfolioRating": "Exceptional",
        "summary": "This student presents a compelling profile...",
        "areas": {
          "academics": {
            "analysis": "The student has a strong GPA...",
            "recommendations": [
              "Take AP Calculus BC to align with [Target College’s] rigorous academic expectations.",
              "Raise SAT Math score to 770 to meet [Target College’s] middle 50% range (750-790).",
              "Conduct independent research in [intended major] and submit findings to a peer-reviewed journal.",
              "Enroll in a dual-enrollment program at a local university to showcase college-level coursework."
            ]
          },
          "extracurriculars": {
            "analysis": "The student has deep involvement in...",
            "recommendations": [
              "Expand leadership role in [activity] by founding a new initiative.",
              "Compete in [national competition] to gain recognition in [field].",
              "Quantify impact by tracking growth metrics (e.g., 'raised $10,000 for X cause').",
              "Secure an internship in [field] to strengthen real-world experience."
            ]
          },
          "awards": {
            "analysis": "The student has received notable awards in...",
            "recommendations": [
              "Apply for the Regeneron STS competition.",
              "Submit work to the MIT Think Scholars program.",
              "Compete in the Conrad Challenge for recognition in innovation."
            ]
          },
          "scholarships": {
            "analysis": "The student is eligible for several competitive scholarships...",
            "recommendations": [
              "Apply for the Coca-Cola Scholars Program ($20,000).",
              "Submit application for the Davidson Fellows Scholarship ($50,000).",
              "Consider the Jack Kent Cooke Foundation scholarship for high-achieving students with financial need."
            ]
          }
        },
        "collegeListEvaluation": {
          "analysis": "The student’s college list is well-balanced...",
          "recommendations": [
            "Add [Reach College] for its strong [program].",
            "Remove [Target College] as its median GPA is significantly higher than the student’s.",
            "Explore [Safety School] due to strong merit aid opportunities."
          ]
        }
      }
      \`\`\`
      
      ---
      
      ### **Critical Guidelines**
      - **Every section must contain at least 6-8 recommendations.**
      - **Justify all suggestions with specific benchmarks, data points, or strategic reasoning.**
      - **Be as detailed, insightful, and data-driven as possible.**
      - **Return only JSON. No explanations, no formatting, no extra text.**`;

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content: "You are an expert college admissions advisor.",
        },
        { role: "user", content: prompt },
      ],
      temperature: 0.7,
    });

    if (!response.choices || response.choices.length === 0) {
      return res
        .status(500)
        .json({ error: "OpenAI API returned no response." });
    }

    await db
      .collection("users")
      .updateOne(
        { userId: req.user },
        { $set: { recommended: response.choices[0].message.content } }
      );

    const aiResponse = response.choices[0].message.content;
    return res.json({ evaluation: aiResponse });
  } catch (error) {
    console.error("Error:", error);
    return res
      .status(500)
      .json({ error: "An error occurred while processing the request." });
  }
};

exports.getAnalysis = async (req, res) => {
  if (!db) {
    db = getDb();
  }
  try {
    const user = await db.collection("users").findOne({ userId: req.user });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    return res.json({ recommended: user.recommended });
  } catch (error) {
    console.error("Error:", error);
    return res
      .status(500)
      .json({ error: "An error occurred while processing the request." });
  }
};

exports.reviewEssay = async (req, res) => {
  if (!db) {
    db = getDb();
  }
  try {
    const { essay } = req.body;
    const userId = req.user;

    if (!essay || typeof essay !== "string" || essay.trim().length === 0) {
      return res.status(400).json({
        success: false,
        message: "Valid essay text is required",
      });
    }

    if (essay.length > 10000) {
      return res.status(400).json({
        success: false,
        message: "Essay exceeds maximum length of 10,000 characters",
      });
    }

    const user = await db.collection("users").findOne({ userId });
    const now = new Date();
    const currentMonthStart = new Date(now.getFullYear(), now.getMonth(), 1);

    const monthlyReviews = user.essayReviews
      ? user.essayReviews.filter((date) => new Date(date) >= currentMonthStart)
      : [];

    if (monthlyReviews.length >= 3) {
      return res.status(429).json({
        success: false,
        message: "Monthly limit of 3 essay reviews exceeded",
      });
    }

    const defaultPrompt = `Act as a elite college essay specialist. Provide EXTREMELY DETAILED, line-by-line feedback focused on actionables. Analyze:

    **Core Elements**
    1. Grammar/Syntax (highlight specific errors)
    2. Tone (formal/informal balance)
    3. Word Choice (precise vs vague language)
    4. Diction (academic vs conversational) 
    5. Sentence Structure (variety/complexity)
    6. Narrative Flow (transitions/pacing)
    7. Hook Effectiveness (opening impact)
    8. Unique Voice (authenticity markers)
    9. Concrete Examples (specificity level)
    10. Admissions Fit (alignment with college values)
    
    **Response Requirements**
    - For EACH category: 3-5 SPECIFIC examples FROM THE ESSAY
    - Provide a minimum of 7 (recommended more) suggested improvements
    - Direct quotes from text with line numbers
    - Concrete revision suggestions
    - Percentage ratings reflecting skill level
    
    **JSON Template**
    \`\`\`json
    {
      "ratings": {
        "grammar": <1-100>, 
        "tone": <1-100>,
        "word_choice": <1-100>,
        "diction": <1-100>,
        "sentence_structure": <1-100>,
        "narrative_flow": <1-100>,
        "hook": <1-100>,
        "uniqueness": <1-100>,
        "examples": <1-100>,
        "admissions_fit": <1-100>
      },
      "strengths": [
        {
          "category": "Word Choice",
          "example": "\"The laboratory's sterile environment\" (line 12)",
          "analysis": "Excellent precise terminology showing scientific awareness"
        }
      ],
      "improvements": [
        {
          "category": "Tone",
          "excerpt": "\"I kinda stumbled into research\" (line 8)",
          "issue": "Overly casual for academic context",
          "fix": "\"My research journey began unexpectedly\"",
          "rationale": "Maintains authenticity while using more formal academic register"
        }
      ],
      "overall_impression": {
        "summary": "Strong foundation needing polish in...",
        "top_3_priorities": [
          "Revise informal phrases in lines 8,15,22",
          "Vary sentence starters in paragraphs 3-4", 
          "Add 2-3 discipline-specific terms in methods section"
        ]
      }
    }
    \`\`\`
    
    **Rules**
    1. Minimum 15 specific examples TOTAL
    2. Every improvement MUST include:
       - Exact text excerpt 
       - Line number reference
       - Suggested revision
       - Brief technical rationale
    3. Never use vague statements - ALWAYS anchor in text
    4. Prioritize changes with biggest admissions impact

    ** RETURN ONLY A JSON FILE, DO NOT PROVIDE TEXT RESPONSES, DO NOT WRAP IT IN A CODE BLOCK. **

    **OTHER INSTRUCTIONS:**
    1. Move ALL parenthetical line numbers inside the quotes.
    2. Escape any internal double quotes in examples:
    "example": "\"I was angry\" (line 6)"
    
    Essay: ${sanitizeEssayInput(essay)}`;

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content: "You are a college admissions essay expert.",
        },
        { role: "user", content: defaultPrompt },
      ],
      temperature: 0.4,
      max_tokens: 1500,
    });

    const feedback = response.choices[0].message.content;

    await db
      .collection("users")
      .updateOne(
        { userId },
        { $push: { essayReviews: new Date().toISOString() } }
      );

    res.status(200).json({
      success: true,
      feedback: feedback,
      reviewsRemaining: 3 - (monthlyReviews.length + 1),
    });
  } catch (error) {
    console.error("Essay review error:", error);
    res.status(500).json({
      success: false,
      message: "Error processing essay review",
    });
  }
};

exports.getSettings = async (req, res) => {
  if (!db) {
    db = getDb();
  }
  try {
    let defaultSettings = {
      apptwo: false,
      emailtwo: false,
      emailNot: true,
    };
    const user = await db.collection("users").findOne({ userId: req.user });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    return res.json({
      success: true,
      settings: user.settings ? user.settings : defaultSettings,
      email: user.email,
      name: user.name,
      auth: user.auth,
    });
  } catch (error) {
    console.error("Error:", error);
    return res
      .status(500)
      .json({ error: "An error occurred while processing the request." });
  }
};

exports.submitCollegePreferences = async (req, res) => {
  if (!db) {
    db = getDb();
  }
  try {
    const studentData = req.body;

    if (!studentData) {
      return res.status(400).json({
        success: false,
        message: "Missing student data",
      });
    }
    const user = await db.collection("users").findOne({ userId: req.user });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const allowedFields = [
      "location",
      "type",
      "goodMajor",
      "tuition",
      "athletics",
      "academicRigor",
      "diversity",
      "internships",
      "studyAbroad",
      "housing",
      "climate",
      "socialLife",
      "campusSize",
      "gpa",
    ];

    const validatedData = {};

    for (const field of allowedFields) {
      if (studentData[field] !== undefined) {
        validatedData[field] = sanitizeInput(studentData[field]);
      }
    }

    const userVector = encodeUserPreferences(validatedData);

    await db
      .collection("users")
      .updateOne(
        { userId: req.user },
        { $set: { collegePref: validatedData, collegePrefVector: userVector } }
      );
    return res.json({ success: true });
  } catch (error) {
    console.error("Error:", error);
    return res
      .status(500)
      .json({ error: "An error occurred while processing the request." });
  }
};

exports.getCollegePreferences = async (req, res) => {
  if (!global.db) {
    global.db = getDb();
  }

  try {
    let { pg } = req.query;
    pg = Number(pg)
    if (!pg || pg < 1 || !Number.isInteger(pg) || pg === 'NaN' || pg === 'Infinity') {
      pg = 1;
    }

    const rawData = fs.readFileSync("./info/colleges.json", "utf-8");
    const universities = JSON.parse(rawData).filter(uni =>
      Array.isArray(uni.normalizedVector) &&
      uni.normalizedVector.every(Number.isFinite)
    );

    const user = await global.db.collection("users").findOne({ userId: req.user });
    if (!user?.collegePrefVector) {
      return res.status(404).json({ success: false, message: "No preferences found" });
    }

    let userVector = new Float32Array(user.collegePrefVector);
    const userNorm = Math.sqrt(userVector.reduce((sum, val) => sum + val * val, 0));
    if (userNorm === 0) {
      return res.status(400).json({ success: false, message: "User preference vector norm is zero" });
    }

    const resultsPromises = universities.map(async (uni) => {
      let uniVector = new Float32Array(uni.normalizedVector);
      if (userVector.length !== uniVector.length) {
        const maxLength = Math.max(userVector.length, uniVector.length);
        const paddedUserVector = new Float32Array(maxLength);
        const paddedUniVector = new Float32Array(maxLength);
        paddedUserVector.set(userVector);
        paddedUniVector.set(uniVector);
        userVector = paddedUserVector;
        uniVector = paddedUniVector;
      }

      let dotProduct = 0;
      for (let i = 0; i < userVector.length; i++) {
        dotProduct += userVector[i] * uniVector[i];
      }
      const uniNorm = Math.sqrt(uniVector.reduce((sum, val) => sum + val * val, 0));
      if (uniNorm === 0) return null;
      const similarity = dotProduct / (userNorm * uniNorm);

      const extraDetails = await getCachedCollegeData(uni.name, uni);

      return {
        name: uni.name,
        match_percentage: Number(((similarity + 1) * 50).toFixed(2)),
        similarity: similarity,
        description: extraDetails.description ||
          `${uni.name} is a ${uni.type} institution located in ${uni.location} offering tuition around $${uni.tuition}.`,
        acceptance_rate: extraDetails.acceptance_rate || "N/A",
        header_image: extraDetails.header_image || "https://via.placeholder.com/800x400?text=No+Image+Available",
        details: {
          location: extraDetails.location || uni.location,
          tuition: extraDetails.tuition || uni.tuition,
          athletics: uni.athletics,
          academicRigor: uni.academicRigor,
          diversity: uni.diversity,
          internships: uni.internships,
          studyAbroad: uni.studyAbroad,
          housing: uni.housing,
          climate: uni.climate,
          socialLife: uni.socialLife,
          campusSize: extraDetails.collegeSize,
          gpa: uni.gpa,
        },
      };
    });

    const resultsArray = await Promise.all(resultsPromises);
    const sortedResults = resultsArray
      .filter(item => item !== null)
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, 20 * pg);

    return res.json({ results: sortedResults });
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({
      error: "Search operation failed",
      details: error.message,
    });
  }
};