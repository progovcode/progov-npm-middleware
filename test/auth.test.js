import
	jwt
from 'jsonwebtoken';
import
	sinon
from 'sinon';
import
	sinonChai
from 'sinon-chai';
import
	chai,
	{
		expect
} from 'chai';
import {
	createRequest,
	createResponse
} from 'node-mocks-http';

chai.use(sinonChai);

import {
	auth,
	validateHeaders
} from '../src';

describe('Given middlewares', () => {

	let next, req, res, jwtStub;
		
	before(() => {
		jwtStub = sinon.stub(jwt, 'verify');
	});
	
	beforeEach(() => {
		next = sinon.spy();
		req = createRequest({
			baseUrl: '/test',
			headers: {
				authorization: 'Bearer token'
			}
		});
		res = createResponse();
		res.json = sinon.spy();
		jwtStub.reset();
	});
	
	after(() => {
		jwtStub.restore();
	});

	describe('Given auth', () => {
		
		it('should call next once if user is authorized', () => {

			jwtStub.returns({
				email: 'test@test.test',
				roles: [
					{
						rights: [
							{
								url: '/test'
							}
						]
					}
				]
			});
			
			auth(req, res, next);
			expect(next).to.have.been.calledOnce;
		});
		
		it('should return 403 if access is denied for the user', () => {

			jwtStub.returns({
				email: 'test@test.test',
				roles: [
					{
						rights: [
							{
								url: '/notValid'
							}
						]
					}
				]
			});
			
			auth(req, res, next);
			expect(res.json).to.have.been.calledWith({
				reason: 'Access Denied'
			});
			expect(res.statusCode).to.be.equal(403);
		});
		
		it('should return 400 if headers are not valid', () => {
			
			req.headers = {
				authorization: 'token'
			};

			auth(req, res, next);

			expect(res.statusCode).to.be.equal(400);
			expect(res.json).to.have.been.calledWith({
				reason: 'Access token is required'
			});
		});
		
		it('should return 500 if an error is thrown', () => {
			
			jwtStub.throws({ error: 'Error' });

			auth(req, res, next);
			
			expect(res.statusCode).to.be.equal(500);
		});
	});
	
	describe('Given validateHeaders', () => {

		it('should call next once if headers are valid', () => {

			validateHeaders(req, res, next);
			expect(next).to.have.been.calledOnce;
		});
		
		it('should return 400 if cannot validate headers', () => {
			
			req.headers = {
				authorization: 'token'
			};
			
			validateHeaders(req, res, next);

			expect(res.statusCode).to.be.equal(400);
			expect(res.json).to.have.been.calledWith({
				reason: 'Cannot validate headers'
			});
		});
	});
});