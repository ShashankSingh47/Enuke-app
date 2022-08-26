const jwt = require('jsonwebtoken')
const User = require('../models/user')

const auth = async(req, res, next) =>{

    try{
        const token = req.header('Authorization').replace('Bearer ','')
        const decoded = jwt.verify(token, 'codeforenc')
        const user = await User.findOne({_id: decoded._id, 'tokens.token': token})

        if(!user){
            throw new Error()
        }

        req.token = token
        console.log('token ', token);
        req.user = user
        next()
    }catch(e){
        res.status(401).send({error: 'Please authenticate.'})
    }

    // console.log('auth middleware');
   
}
module.exports = auth