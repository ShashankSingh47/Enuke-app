const express = require('express')
const User = require('../models/user')
const multer = require('multer')
const  auth = require('../middleware/auth')
const router = new express.Router()


router.post('/users', async(req,res)=>{
    const user = new User(req.body)
   
   try {
       await user.save()
        const token = await user.generateAuthToken()


       res.status(201).send({user, token })
   }catch (e){
       res.status(400).send(e)
   }


})

router.post('/users/login', async (req, res)=>{

    try {

        const user = await User.findByCredentials(req.body.email, req.body.password)
        const token = await user.generateAuthToken()
        res.send({user, token})

    } catch(e){
        res.status(400).send()

    }

})

router.post('/users/logout', auth, async(req,res)=>{
    
    try{
        req.user.tokens = req.user.tokens.filter((token)=>{
            return token.token !== req.token

        })
        await req.user.save()
        res.send()
    }catch(e){
        res.status(500).send()
    }


})


const upload = multer({
        
        limits:{
            fileSize:500000
        },
        fileFilter(req,file,cb){
            if(!file.originalname.match(/\.(jpg|jpeg|png)$/)){

                return cb (new Error('Please upload an image'))

            }
            cb(undefined,true)
        }
})

router.post('/users/me/avatar',auth ,upload.single('avatar'),async (req,res)=>{

    req.user.avatar = req.file.buffer
    await req.user.save()
    res.send()

},(error, req,res,next)=>{
    res.status(400).send({error: error.message})
})


module.exports = router