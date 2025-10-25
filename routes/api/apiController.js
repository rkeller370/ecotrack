const { getDb, initializeMongo } = require("../../config/db");
const { sanitizeInput } = require("../../utils/sanitize");
const {
  validateEmail,
  validatePassword,
} = require("../../utils/validationUtils");
const { getClientIp }  = require("../../utils/getIP");
const { changeIP }  = require("../../utils/ipToLocation");
const { OpenAI } = require("openai");
const axios = require("axios");
const fs = require("fs");
const jwt = require("jsonwebtoken");

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

const initializeDatabase = async () => {
  db = await getDb();
};

let index = null;

initializeDatabase();

exports.addLog = async (req,res) => {
  try {
    let { category,activityType,amount,unit,duration,notes,carbonImpact,carbonSaved } = req.body;

    carbonSaved = carbonSaved ? carbonSaved : 0

    console.log(!category)

    if(!category || !activityType || !amount || !unit || !duration || !carbonImpact) {
      return res.status(400).json({
        success: false,
        response: "Invalid paramaters"
      })
    }

    const user = await db.collection("users").findOne({ userId: req.user });

    if(!user) { 
      return res.status(403).json({
        success: false,
        message: "Auth error"
      })
    }

    await db.collection('users').updateOne({userId: req.user}, {$push: {
      activities: {id: Date.now(),timestamp: new Date().toISOString(),category: category,activityType: activityType,amount: amount,unit: unit,duration: duration,notes: notes,carbonImpact: carbonImpact,carbonSaved: carbonSaved}
    }})

    return res.status(200).json({
      success: true
    })
  } catch (err) {
    console.error(err)
    return res.status(500).json({
      success: false,
      message: "Internal server error"
    })
  }
}

exports.ecoSuggestions = async (req, res) => {
  try {
    const ip = await getClientIp(req)
    const location = await changeIP(ip)

    const prompt = `
    You are an assistant that suggests eco-friendly and sustainable activities, shops, or events in a given location. 
    Focus on specific, actionable recommendations such as local farmers markets, sustainable shops, community recycling events, trails, surronding nature, community cleanups, etc. 
    
    Location context: ${location} (or IP ${ip})
    
    Return the response strictly in **valid JSON** with the following structure:
    
    [
      {
        "name": "string",                // Name
        "description": "string",         // One line description
        "address": "string",             // Street address or general area
        "website": "string",             // Website URL (or "" if none available)
        "recommend_icon": "string"       // Font Awesome icon suggestion (e.g., 'fa-leaf', 'fa-store', 'fa-recycle')
      }
    ]
    
    Rules:
    - Provide 5 recommendations.
    - YOU MUST PROVIDE SUGGESTIONS AROUND THE INPUTTED LOCATION
    - Do not include extra text, explanations, or formatting — only the raw JSON.
    - IF YOU ARE NOT POSITIVE THAT THE WEBSITE IS CORRECT OR NOT 100% SURE IT EXISTS **DO NOT INCLUDE IT**
    - DO NOT INCLUDE CODE BLOCK, DO NOT INCLUDE THE \`\`\` JSON and \`\`\` at the end
    `

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content: "You are an eco-friendly adviser.",
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

    const aiResponse = response.choices[0].message.content;

    await db
    .collection("users")
    .updateOne(
      { userId: req.user },
      { $set: { ecoRecommendations: aiResponse } }
    );

    return res.status(200).json({
      success: true,
      response: aiResponse,
    })
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      success: false,
      message: "Internal server error"
    })
  }
}

exports.getVolunteerEvents = async (req, res) => {
  try {
    const user = await db.collection("users").findOne({ userId: req.user });
    const events = await db.collection("events").find().toArray()

    if(!user) {
      return res.status(403).json({
        success: false,
        message: 'Auth error',
      })
    }
    
    return res.status(200).json({
      success: true,
      userEvents: user.events || [],
      allEvents: events || [],
    })
  } catch (err) {
    console.error(err)
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    })
  }
}

exports.closeRegistration = async (req,res) => {
  try {

  } catch (err) {
    console.error(err)
    return res.status(500).json({
      success: false,
      message: "Internal server error"
    })
  }
}

exports.dailySuggestion = async (req,res) => {
  try {
    const user = await db.collection('users').findOne({userId: req.user})
    if(!user) {
      return res.status(403).json({
        success: false,
        message: "Auth err"
      })
    }

    if(user.dailySuggestion) {
      if (Date.now() - new Date(user.dailySuggestion.timestamp).getTime() >= 24 * 60 * 60 * 1000) {
      } else {
        return res.status(200).json({
          success: true,
          message: user.dailySuggestion.message,
        })
      }  
    }

    const ip = await getClientIp(req)
    const location = await changeIP(ip)

    const prompt = `
    You are an assistant that analyzes a user's eco-friendly activities and provides one concise, actionable suggestion for improvement.
    If a valid location is provided (not "undefined"), base your suggestion on that location. 
    If the location is undefined, provide a general, globally applicable eco-friendly suggestion.
    
    Context:
    - Location: ${location} (IP: ${ip})
    - User Activities: ${JSON.stringify(user.activities)}
    
    Rules:
    - Return only one brief suggestion (1–2 sentences).
    - Do NOT include any explanations, extra text, or formatting — just the suggestion itself.
    - Do NOT include uncertain or unverifiable local details.
    - If possible, include potential impact stats like how much you could save in lbs of CO2.
    `

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content: "You are an eco-friendly adviser.",
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

    const aiResponse = response.choices[0].message.content;

    await db.collection('users').updateOne({userId: req.user}, {$set: { dailySuggestion: {message: aiResponse,timestamp: new Date()} }})

    return res.status(200).json({
      success: true,
      message: aiResponse,
    })
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      success: false,
      message: "Internal server error"
    })
  }
}

exports.registerEvent = async (req, res) => {
  try {
    const { eventId } = req.body;
    if(!eventId || !String(eventId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid paramaters"
      })
    }

    const user = await db.collection("users").findOne({ userId: req.user })
    if(!user) {
      return res.status(403).json({
        success: false,
        message: 'Auth error'
      })
    }

    const event = await db.collection("events").findOne({id: eventId})
    if(!event) {
      return res.status(400).json({
        success: false,
        message: "Event not found"
      })
    }

    if(event.registeredVolunteers >= event.requiredVolunteers) {
      return res.status(400).json({
        success: false,
        message: "Max volunteers reached"
      })
    }

    event.registeredVolunteers.forEach((volunteer) => {
      if(volunteer.email == user.email) {
        return res.status(400).json({
          success: false,
          message: "Already registered for this event"
        })
      }
    })

    await db.collection('events').updateOne({id: eventId}, {$push: {
      registeredVolunteers: {name: user.name,email: user.email}
    }, $inc: {
      volunteersRegistered: 1
    }}) 

    await db.collection('users').updateOne({userId: req.user}, {$push: {
      events: {eventId: eventId,date: event.date,hours: event.duration}
    }})

    return res.status(200).json({
      success: true,
      message: `Successfully registered ${user.name} for ${event.title}. (${event.volunteersRegistered++}/${event.volunteersNeeded} volunteer)`
    })
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      success: false,
      message: "Internal server error"
    })
  }
}

exports.unregisterEvent = async (req, res) => {
  try {
    const { eventId } = req.body;
    if(!eventId || !String(eventId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid params"
      })
    }

    const user = await db.collection("users").findOne({userId: req.user})
    if(!user) {
      return res.status(403).json({
        success: false,
        message: "Auth err"
      })
    }

    const event = await db.collection("events").findOne({id: eventId})
    if(!event) {
      return res.status(400).json({
        success: false,
        message: "Event not found"
      })
    }

    await db.collection("events").updateOne(
      { id: eventId },
      {
        $pull: {
          registeredVolunteers: { email: user.email }
        },
        $inc: {
          volunteersRegistered: -1
        }
      }
    );
    
    await db.collection("users").updateOne(
      { userId: req.user },
      {
        $pull: {
          events: { eventId: eventId }
        }
      }
    );
    
    return res.status(200).json({
      success: true,
    })
  } catch (err) {
    console.error(err)
    return res.status(500).json({
      success: false,
      message: "Internal server error"
    })
  }
}

exports.createEvent = async (req,res) => {
  try {
    const eventData = req.body
    if(!eventData) {
      return res.status(400).json({
        success: false,
        message: "Invalid params"
      })
    }

    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let eventId = "";
    let length = 8;
    for (let i = 0; i < length; i++) {
      eventId += chars[Math.floor(Math.random() * chars.length)];
    }

    let event = {
      id: eventId,
      title: sanitizeInput(eventData.title || ""),
      status: sanitizeInput(eventData.status || ""),
      date: eventData.date,
      time: eventData.time,
      location: eventData.location,
      description: sanitizeInput(eventData.description),
      organizer: eventData.organizer,
      volunteersNeeded: eventData.volunteersNeeded,
      volunteersRegistered: 0,
      duration: eventData.duration,
      category: sanitizeInput(eventData.category),
      impact: sanitizeInput(eventData.impact),
      requirements: sanitizeInput(eventData.requirements),
      lat: eventData.lat,
      lon: eventData.lon,
      creatorId: req.user,
      registeredVolunteers: [],
    }

    await db.collection('events').insertOne(event);
    
    return res.status(200).json({
      success: true,
    })
  } catch (err) {
    console.error(err)
    return res.status(500).json({
      success: false,
      message: "Internal server error"
    })
  }
}