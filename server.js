const express = require("express")
const axios = require("axios")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cookie = require("cookie-parser")
const fs = require("fs")
const crypto = require("crypto")
const https = require("https")
const http = require("http")
const net = require("net")

const app = express()

const PORT = process.env.PORT || 3000
const OWNER_KEY = process.env.OWNER_KEY || "owner"
const JWT = process.env.JWT || "secret"

app.use(express.json({
    limit:"2mb"
}))

app.use(cookie())

app.use(express.static("public"))

const load = ()=>{

    try{

        return JSON.parse(
            fs.readFileSync("data.json","utf8")
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

    if(!token)
        return res.sendStatus(401)

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
            maxRedirects:5,
            validateStatus:()=>true,
            headers:{
                "user-agent":"Mozilla/5.0"
            }
        })

        return {
            status:res.status,
            ping:Date.now()-start
        }

    },

    async browser(url){

        const start = Date.now()

        const res = await axios.get(url,{
            timeout:20000,
            maxRedirects:5,
            validateStatus:()=>true,
            headers:{
                "user-agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125 Safari/537.36",

                "accept":
                "text/html,application/xhtml+xml,application/xml",

                "accept-language":
                "en-US,en;q=0.9",

                "cache-control":
                "no-cache"
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
            timeout:10000,
            validateStatus:()=>true
        })

        return {
            status:res.status,
            ping:Date.now()-start
        }

    },

    async status(url){

        const start = Date.now()

        return new Promise((resolve,reject)=>{

            const lib =
                url.startsWith("https")
                ? https
                : http

            const req = lib.request(
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

            req.on("timeout",()=>{

                req.destroy()

                reject("timeout")

            })

            req.end()

        })

    },

    async ping(url){

        const start = Date.now()

        return new Promise((resolve,reject)=>{

            const u = new URL(url)

            const port =
                u.protocol==="https:"
                ? 443
                : 80

            const socket =
                net.createConnection(
                    port,
                    u.hostname
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
Uptime: ${m.uptime || 0}%

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

        const data =
            await fn(m.url)

        m.totalChecks =
            (m.totalChecks || 0) + 1

        m.goodChecks =
            (m.goodChecks || 0) + 1

        m.uptime = (
            (
                m.goodChecks /
                m.totalChecks
            ) * 100
        ).toFixed(2)

        m.lastStatus = "online"
        m.lastPing = data.ping
        m.lastCode = data.status
        m.lastError = null
        m.lastCheck = Date.now()
        m.retry = 0

        if(old !== "online"){

            sendWebhook(
                m,
                "up"
            )

        }

    }catch(err){

        m.retry =
            (m.retry || 0) + 1

        if(m.retry < 3)
            return

        m.totalChecks =
            (m.totalChecks || 0) + 1

        m.uptime = (
            (
                m.goodChecks || 0
            ) /
            m.totalChecks * 100
        ).toFixed(2)

        m.lastStatus = "offline"

        m.lastError =
            err.message ||
            String(err)

        m.lastCheck = Date.now()

        if(old !== "offline"){

            sendWebhook(
                m,
                "down"
            )

        }

    }

    save()

}

setInterval(()=>{

    db.monitors.forEach(m=>{

        if(
            Date.now() -
            (m.lastCheck || 0)
            >= m.interval
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
        await bcrypt.hash(
            password,
            10
        )

    db.users.push({

        id:Date.now().toString(),

        username,

        password:hash,

        role:
            key===OWNER_KEY
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

    res.cookie(
        "token",
        token,
        {
            httpOnly:true
        }
    )

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

        id:
            crypto
            .randomBytes(8)
            .toString("hex"),

        user:req.user.id,

        name,

        url,

        method,

        interval:Number(interval),

        webhook,

        tag,

        retry:0,

        totalChecks:0,

        goodChecks:0,

        uptime:"0.00",

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

    Object.assign(
        m,
        req.body
    )

    save()

    res.json({
        success:true
    })

})

app.delete(
    "/api/monitor/:id",
    auth,
    (req,res)=>{

    db.monitors =
        db.monitors.filter(
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

        uptime:m.uptime,

        error:m.lastError,

        lastCheck:m.lastCheck

    })

})

app.get(
    "/api/admin/users",
    auth,
    (req,res)=>{

    if(req.user.role!=="owner")
        return res.sendStatus(403)

    res.json(db.users)

})

app.get(
    "/api/admin/monitors",
    auth,
    (req,res)=>{

    if(req.user.role!=="owner")
        return res.sendStatus(403)

    res.json(db.monitors)

})

app.get(
    "/api/admin/stats",
    auth,
    (req,res)=>{

    if(req.user.role!=="owner")
        return res.sendStatus(403)

    res.json({

        users:db.users.length,

        monitors:
            db.monitors.length,

        online:
            db.monitors.filter(
                x=>
                    x.lastStatus==="online"
            ).length,

        offline:
            db.monitors.filter(
                x=>
                    x.lastStatus==="offline"
            ).length

    })

})

app.get("/",(req,res)=>{

    res.sendFile(
        __dirname +
        "/public/login.html"
    )

})

app.listen(PORT,()=>{

    console.log(
        "running",
        PORT
    )

})
