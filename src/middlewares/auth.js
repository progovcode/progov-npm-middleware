import {
	getConfig
} from 'progov-npm-utils';
import
	jwt
from 'jsonwebtoken';

const PRIVATE_KEY = getConfig('progov.middlewares.auth.private-key');

const isAllowed = (roles, req) => {
	
	if (roles !== null && Array.isArray(roles)) {
		
		for (let role of roles) {
			
			const rights = role.rights;
			if (rights !== null && Array.isArray(rights)) {
				
				for (let right of rights) {
					
					if (right.url === req.baseUrl) {
						
						return true;
					}
				}
			}
		}
	}
	
	return false;
};

const hasValidHeaders = (req) => {

	return req?.headers?.authorization?.split(' ')?.[0] === 'Bearer'
		? true
		: false;
};

export const validateHeaders = (req, res, next) => {

	if (hasValidHeaders(req)) {
		
		return next();
	}

	res.status(400);
	return res.json({
		reason: 'Cannot validate headers'
	});
};

export const auth = (req, res, next) => {
	
	if (hasValidHeaders(req)) {
		
		const token = req?.headers?.authorization?.split(' ')?.[1];
		
		try {
			
			req.user = jwt.verify(token, PRIVATE_KEY);
			
			const roles = req.user.roles;
			
			if (isAllowed(roles, req)) {

				return next();
			}
			
			res.status(403);
			return res.json({
				reason: 'Access Denied'
			});
		} catch (error) {
			
			res.status(500);
			return res.json({
				error
			});
		}
	}
	
	res.status(400);
	return res.json({
		reason: 'Access token is required'
	});
}