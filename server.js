const express = require("express")
const axios = require("axios")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const cookie = require("cookie-parser")
const fs = require("fs")
const crypto = require("crypto")
const https = require("https")
const http = require("http")
const net = require("net")
const { chromium } = require("playwright")

const app = express()

const PORT = process.env.PORT || 3000
const OWNER_KEY = process.env.OWNER_KEY || "owner"
const JWT = process.env.JWT || "secret"

app.use(express.json())
app.use(cookie())
app.use(express.static("public"))

const load = ()=>{
    try{
        return JSON.parse(
            fs.readFileSync("data.json")
        )
    }catch{
        return {
            users:[],
            monitors:[]
        }
    }
}

const db = load()

const save = ()=>{
    fs.writeFileSync(
        "data.json",
        JSON.stringify(db,null,2)
    )
}

const auth = (req,res,next)=>{
    const token = req.cookies.token

    if(!token)
        return res.sendStatus(401)

    try{
        req.user = jwt.verify(token,JWT)
        next()
    }catch{
        res.sendStatus(401)
    }
}

const apiAuth = (req,res,next)=>{
    const token = req.headers.authorization

    const user = db.users.find(
        x=>x.apiToken===token
    )

    if(!user)
        return res.sendStatus(401)

    req.user = user

    next()
}

const methods = {

    async curl(url){

        const start = Date.now()

        const res = await axios.get(url,{
            timeout:15000,
            headers:{
                "user-agent":"Mozilla/5.0"
            }
        })

        return {
            status:res.status,
            ping:Date.now()-start
        }
    },

    async head(url){

        const start = Date.now()

        const res = await axios.head(url,{
            timeout:10000
        })

        return {
            status:res.status,
            ping:Date.now()-start
        }
    },

    async browser(url){

        const start = Date.now()

        const browser = await chromium.launch({
            headless:true,
            executablePath:
                process.env.PLAYWRIGHT_BROWSERS_PATH
                ? undefined
                : "/opt/render/.cache/ms-playwright/chromium-*/chrome-linux/chrome",

            args:[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu"
            ]
        })

        const page = await browser.newPage()

        await page.goto(url,{
            waitUntil:"networkidle",
            timeout:25000
        })

        await browser.close()

        return {
            status:200,
            ping:Date.now()-start
        }
    },

    async ping(url){

        const start = Date.now()

        return new Promise((resolve,reject)=>{

            const host = new URL(url).hostname

            const socket = net.createConnection(
                80,
                host
            )

            socket.setTimeout(10000)

            socket.on("connect",()=>{
                socket.destroy()

                resolve({
                    status:200,
                    ping:Date.now()-start
                })
            })

            socket.on("error",reject)

            socket.on("timeout",()=>{
                socket.destroy()
                reject("timeout")
            })
        })
    },

    async status(url){

        const start = Date.now()

        return new Promise((resolve,reject)=>{

            const fn = url.startsWith("https")
                ? https
                : http

            const req = fn.request(
                url,
                {
                    method:"GET",
                    timeout:10000
                },
                res=>{
                    resolve({
                        status:res.statusCode,
                        ping:Date.now()-start
                    })
                }
            )

            req.on("error",reject)

            req.end()
        })
    }
}

async function sendWebhook(
    m,
    type
){

    if(!m.webhook)
        return

    try{

        await axios.post(
            m.webhook,
            {
                content:
`${m.tag || ""}

${type==="up"
? "🟢 ONLINE"
: "🔴 OFFLINE"}

Name: ${m.name}
URL: ${m.url}
Method: ${m.method}
Ping: ${m.lastPing || 0}ms
Status: ${m.lastCode || 0}

${m.lastError || ""}`
            }
        )

    }catch{}
}

async function check(m){

    const old = m.lastStatus

    try{

        const fn = methods[m.method]

        if(!fn)
            return

        const data = await fn(m.url)

        m.lastStatus = "online"
        m.lastPing = data.ping
        m.lastCode = data.status
        m.lastCheck = Date.now()
        m.lastError = null
        m.retry = 0

        if(old !== "online"){
            sendWebhook(m,"up")
        }

    }catch(err){

        m.retry = (m.retry || 0) + 1

        if(m.retry < 3){
            return
        }

        m.lastStatus = "offline"
        m.lastError =
            err.message || String(err)

        m.lastCheck = Date.now()

        if(old !== "offline"){
            sendWebhook(m,"down")
        }
    }

    save()
}

setInterval(()=>{

    db.monitors.forEach(m=>{

        if(
            Date.now()-m.lastCheck >=
            m.interval
        ){
            check(m)
        }

    })

},15000)

app.post(
    "/api/register",
    async(req,res)=>{

    const {
        username,
        password,
        key
    } = req.body

    if(
        !username ||
        !password
    ){
        return res.json({
            error:"missing"
        })
    }

    if(
        db.users.find(
            x=>x.username===username
        )
    ){
        return res.json({
            error:"exist"
        })
    }

    const hash =
        await bcrypt.hash(password,10)

    db.users.push({
        id:Date.now().toString(),
        username,
        password:hash,
        role:key===OWNER_KEY
            ? "owner"
            : "user",
        apiToken:crypto
            .randomBytes(32)
            .toString("hex")
    })

    save()

    res.json({
        success:true
    })
})

app.post(
    "/api/login",
    async(req,res)=>{

    const {
        username,
        password
    } = req.body

    const user = db.users.find(
        x=>x.username===username
    )

    if(!user){
        return res.json({
            error:"notfound"
        })
    }

    const ok =
        await bcrypt.compare(
            password,
            user.password
        )

    if(!ok){
        return res.json({
            error:"wrong"
        })
    }

    const token = jwt.sign({
        id:user.id,
        username:user.username,
        role:user.role
    },JWT)

    res.cookie("token",token)

    res.json({
        success:true
    })
})

app.get(
    "/api/me",
    auth,
    (req,res)=>{

    const user = db.users.find(
        x=>x.id===req.user.id
    )

    res.json({
        id:user.id,
        username:user.username,
        role:user.role,
        apiToken:user.apiToken
    })
})

app.get(
    "/api/monitors",
    auth,
    (req,res)=>{

    res.json(
        db.monitors.filter(
            x=>x.user===req.user.id
        )
    )
})

app.post(
    "/api/monitor",
    auth,
    (req,res)=>{

    const {
        name,
        url,
        method,
        interval,
        webhook,
        tag
    } = req.body

    db.monitors.push({
        id:Date.now().toString(),
        user:req.user.id,
        name,
        url,
        method,
        interval:Number(interval),
        webhook,
        tag,
        retry:0,
        lastStatus:"waiting",
        lastPing:0,
        lastCode:0,
        lastCheck:0,
        lastError:null
    })

    save()

    res.json({
        success:true
    })
})

app.put(
    "/api/monitor/:id",
    auth,
    (req,res)=>{

    const m = db.monitors.find(
        x=>
            x.id===req.params.id &&
            x.user===req.user.id
    )

    if(!m)
        return res.sendStatus(404)

    Object.assign(m,req.body)

    save()

    res.json({
        success:true
    })
})

app.delete(
    "/api/monitor/:id",
    auth,
    (req,res)=>{

    db.monitors = db.monitors.filter(
        x=>
            !(
                x.id===req.params.id &&
                x.user===req.user.id
            )
    )

    save()

    res.json({
        success:true
    })
})

app.get(
    "/api/bot/monitors",
    apiAuth,
    (req,res)=>{

    res.json(
        db.monitors.filter(
            x=>x.user===req.user.id
        )
    )
})

app.get(
    "/api/bot/check/:id",
    apiAuth,
    (req,res)=>{

    const m = db.monitors.find(
        x=>
            x.id===req.params.id &&
            x.user===req.user.id
    )

    if(!m)
        return res.sendStatus(404)

    res.json({
        alive:
            m.lastStatus==="online",
        status:m.lastCode,
        ping:m.lastPing,
        error:m.lastError,
        lastCheck:m.lastCheck
    })
})

app.get(
    "/api/admin/users",
    auth,
    (req,res)=>{

    if(req.user.role!=="owner"){
        return res.sendStatus(403)
    }

    res.json(db.users)
})

app.get(
    "/api/admin/monitors",
    auth,
    (req,res)=>{

    if(req.user.role!=="owner"){
        return res.sendStatus(403)
    }

    res.json(db.monitors)
})

app.get("/",(req,res)=>{
    res.sendFile(
        __dirname +
        "/public/login.html"
    )
})

app.listen(PORT,()=>{
    console.log("running",PORT)
})
