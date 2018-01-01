/**
 * 	joera/joera_client.c
 *	Complete joera client interface implementation
 *	Copyright (C) 2017 Mohammad Mohammadi 
 */

#include <pthread.h>
#include <client/joeraclient.h>
#include <stdio.h>
#include <stdlib.h>
#include <joera/error.h>
#include <joera/types.h>
#include <joera/validate.h>
#include <joera/message.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/select.h>
#include <sys/time.h>
#include <client/net.h>


static inline void settime (struct timeval *t , long sec ,
				long usec)
{
	t->tv_sec = sec;
	t->tv_usec = usec;	
}


/**
 * joera_send_req : send a request to server.
 * interface functions use this to send request and 
 * receive answer.
 * @req : request
 * @res : received response
 * @encoder : requst message ecnoder 
 * @decoder : response message decoder
 */
static int joera_send_request(struct joera_req_msg  *req , 
	struct joera_res_msg *res ,
        msglen_t (*encoder)(struct joera_msg *, uint8_t * , msglen_t), 
	void (*decoder)(struct joera_msg * , uint8_t * , msglen_t) )
{
	/* connect to the server */
	int sd = socket(AF_INET , SOCK_STREAM | SOCK_NONBLOCK , 0);
	if (sd < 0)
		return -1;
		
	int status; 
	struct timeval t;
	settime(&t , 20 , 0);
	
	status = joera_connect (sd , &t);
	if (status) {
		close(sd);
		return status;	
	}	

	printf("Connected to the server...\n");
	/* encode message */
	
	uint8_t *msg_buf;
	msg_buf = (uint8_t *)malloc(MSGSIZE);
	if (!msg_buf) {
		close(sd);
		return J_ENOMEM;
	}
		
	req->msg.len = (encoder == NULL ?
			0 : encoder((struct joera_msg *)req , 
					 msg_buf , MSGSIZE) ) ;
	/* encode header */
	uint8_t reqhdr_buf[REQMSGSIZE]; /* request header buffer */
	encode_request_header(req , reqhdr_buf);
	
	/* send header */
	settime (&t , 20 , 0);
	
	status =  joera_send(sd, reqhdr_buf , REQMSGSIZE , &t);
	if (status) {
		close(sd);
		free(msg_buf);
		return status;	
	}

	printf("Message Sent...\n");
	/* send message */
	settime(&t, 20 , 0);
	status = joera_send(sd , msg_buf , req->msg.len , &t);
	if (status){
		close(sd);
		return status;	
	}

	/* receive response header */
	settime(&t , 20 , 0);
	uint8_t reshdr_buf[RESMSGSIZE]; /* response header buffer */
	status = joera_recv(sd , reshdr_buf , RESMSGSIZE , &t);
	if (status) {
		free(msg_buf);
		close(sd);
		return status;	
	}	

	printf("Header received...\n");
	decode_response_header(res , reshdr_buf);
	
	if (res->msg.len <= 0) { /* no more data */
		close(sd);
		return res->res;
	}
	
	/* receive message */
	settime(&t , 20 , 0);
	status = joera_recv(sd , msg_buf , res->msg.len , &t);
	if (status){
		free(msg_buf);
		close(sd);
		return status;	
	}

	printf("Message received...\n");
	/* decode message */
	decoder((struct joera_msg *)res , msg_buf , res->msg.len);
	
	close(sd);
	free(msg_buf);
	return res->res;
}

/**
 * joera_signup : signup a new user
 * @appid : application identifier 
 */
int joera_signup(appid_t appid , const char *username , 
	const char *password, const char *fname , const char *lname)
{
	if (validate_username(username))
		return J_EINV_USERNAME;
	
	if (validate_password(password))
		return J_EINV_PASSWD;
	
	if (validate_fname(fname))
		return J_EINV_FNAME;
	
	if (lname && validate_lname(lname))
		return J_EINV_LNAME;
	
	struct joera_signup_req_msg request;
	memset(&request , 0 , sizeof(struct joera_signup_req_msg));
	
	request.header.appid = appid;
	request.header.msg.type = J_REQ_SIGNUP;
	strcpy(request.username , username);
	strcpy(request.password , password);
	strcpy(request.fname , fname);
	if (lname)
		strcpy(request.lname , lname);
	
	struct joera_res_msg response;
	memset(&response , 0 , sizeof(struct joera_res_msg));
	
	/* communicate with the server */	
	int status;
	status = joera_send_request((struct joera_req_msg *)&request,
				    &response , 
		encode_signup_request , NULL);

	
	if (!status && (response.msg.type != J_RES_SIGNUP)) 
		return J_EUNDEF_RES;

	return response.res; 	
}

/**
 * joera_sign : signin to the system
 * @appid : application identifier
 * @sessionid_buf : received sessionid will be 
 *	stored in this buffer.
 */ 
int joera_signin(appid_t appid , const char *username ,
		const char *password , uint8_t *sessionid_buf) 		
{
	if (validate_username(username)) 
		return J_EINV_USERNAME;
	if (validate_password(password))
		return J_EINV_PASSWD;
	
		
	struct joera_signin_req_msg request;
	memset(&request , 0 , sizeof(struct joera_signin_req_msg));
	
	request.header.appid = appid;
	request.header.msg.type = J_REQ_SIGNIN;
	strcpy(request.username , username);
	strcpy(request.password , password);
	
	struct joera_signin_res_msg response;
	memset(&response , 0 , sizeof(struct joera_signin_res_msg));
	/* communicate with the server */	
	int status;
	status = joera_send_request((struct joera_req_msg *)&request ,
		(struct joera_res_msg *) &response,
		 encode_signin_request, decode_signin_response);

	if (!status){
		if (response.header.msg.type != J_RES_SIGNIN)
			return J_EUNDEF_RES;
		else 
			strncpy( sessionid_buf, response.sessionid,
				 SESSIONID_LEN);
	} 
	
	return response.header.res; 
}

/**
 * joera_addtrusteduser : add a user to the trusted list
 */
int joera_addtrusteduser(appid_t appid , uint8_t *sessionid,
		const char *username)
{
	if(validate_username(username))
		return J_EINV_USERNAME;
	
		
	struct joera_addtrusteduser_req_msg request;
	memset(&request , 0 ,
	       sizeof(struct joera_addtrusteduser_req_msg));
	
	request.header.appid = appid;
	request.header.msg.type = J_REQ_ADD_TSD;
	strncpy(request.header.sessionid , sessionid , SESSIONID_LEN);
	strcpy(request.username , username);
	struct joera_res_msg response;

	memset(&response , 0 , sizeof(struct joera_res_msg));

	/* communicate with the server */	
	int status;
	status = joera_send_request((struct joera_req_msg *)&request
		,&response , encode_addtrusteduser_request , NULL);

	if (!status && (response.msg.type != J_RES_ADD_TSD))
		return J_EUNDEF_RES;
		
	return response.res;
}

/**
 * joera_rmtrusteduser : remove a user from trusted users list
 */
 
int joera_rmtrusteduser(appid_t appid , uint8_t *sessionid ,
		const char *username)
{
	if(validate_username(username))
		return J_EINV_USERNAME;
	
		
	struct joera_rmtrusteduser_req_msg request;
	memset(&request, 0, sizeof(struct joera_rmtrusteduser_req_msg));
	
	/* prepare request */
	request.header.appid = appid;
	request.header.msg.type = J_REQ_RM_TSD;
	strncpy(request.header.sessionid , sessionid , SESSIONID_LEN);
	
	struct joera_res_msg response;
	memset(&response , 0 , sizeof(struct joera_res_msg));

	/* communicate with the server */	
	int status;
	status = joera_send_request((struct joera_req_msg *)&request
	,  &response , encode_rmtrusteduser_request , NULL);

	if (!status && (response.msg.type != J_RES_RM_TSD))
		return J_EUNDEF_RES;
		
	return response.res;		

}

/**
 * joera_killsession : kill a session
 */
int joera_killsession(appid_t appid , uint8_t *sessionid , 
		uint8_t *id)
{

	struct joera_killsession_req_msg request;
	memset(&request , 0 , sizeof(struct joera_killsession_req_msg));
	
	/* prepare request */
	request.header.appid = appid;
	request.header.msg.type = J_REQ_KILL_SN;
	strncpy(request.header.sessionid , sessionid , SESSIONID_LEN);
	
	struct joera_res_msg response;
	memset(&response , 0 , sizeof(struct joera_res_msg));

	/* communicate with the server */	
	int status;
	status = joera_send_request((struct joera_req_msg *)&request
		,&response , encode_killsession_request , NULL);

	if (!status && (response.msg.type != J_RES_KILL_SN))
		return J_EUNDEF_RES;
		
	return response.res;		
		
}

/**
 * joera_getinfo : get information about a user
 * @username : specified username
 * @fname : user's first name will be stored in this argument
 * @lname : user's lastname will be stored in this argument
 */
int joera_getinfo (appid_t appid , const char *username,
	char *fname , char *lname)
{
	if (validate_username(username))
		return J_EINV_USERNAME;
		
	struct joera_getinfo_req_msg request;
	memset(&request , 0 , sizeof(struct joera_getinfo_req_msg));
	
	/* prepare request */
	request.header.appid = appid;
	request.header.msg.type = J_REQ_GETINFO;
	strcpy(request.username , username);
	
	struct joera_getinfo_res_msg response;
	memset(&response , 0 , sizeof(struct joera_getinfo_res_msg));

	/* communicate with the server */	
	int status;
	status = joera_send_request((struct joera_req_msg *)&request
		,(struct joera_res_msg *)&response
				    , encode_getinfo_request
		, decode_getinfo_response );

	
	if (!status){
		if (response.header.msg.type != J_RES_GETINFO) 
			return J_EUNDEF_RES;
		else {
			strcpy(fname , response.fname);
			strcpy(lname , response.lname);	
		}
	}
			
	return response.header.res;		
	
}

/**
 * joera_sendmessage : send a message to a user
 * @username : receiver user 
 * @buf : message
 * @buflen : size of message 
 */
int joera_sendmessage(appid_t appid , uint8_t *sessionid , 
	const char *username , const uint8_t *buf, msglen_t buflen)
{
	if (validate_username(username))
		return J_EINV_USERNAME;
		
	struct joera_sendmessage_req_msg *request;
	request = (struct joera_sendmessage_req_msg *)malloc (
		sizeof(struct joera_sendmessage_req_msg));
	if (!request) 
		return J_ENOMEM;
	
	memset(request , '\n' , sizeof(struct joera_sendmessage_req_msg));
	
	/* prepare request */
	request->header.appid = appid;
	request->header.msg.type = J_REQ_SEND_MSG;
	strcpy(request->username , username);
	strncpy(request->header.sessionid, sessionid , SESSIONID_LEN);
	request->msglen = buflen;
	memcpy(request->message, buf, request->msglen);
	
	struct joera_res_msg response;
	memset(&response , 0 , sizeof(struct joera_res_msg));
	
	/* communicate with the server */	
	int status;
	status = joera_send_request((struct joera_req_msg *)request
		,&response , encode_sendmessage_request 
		, NULL );

	free(request);
	if (!status && (response.msg.type != J_RES_SEND_MSG))
		return J_EUNDEF_RES;
			
	return response.res;		
			
}

/**
 * joera_setlistener : set a listern for the session 
 */
int joera_setlistener(appid_t appid , uint8_t *sessionid)
{
	int status;
	status = pthread_mutex_lock(&(joera_listener.mutex));
	if (status){
		errno = status;
		return -1;
	}

	if (joera_listener.isconnected){
		pthread_mutex_unlock(&(joera_listener.mutex));
		return J_ECONNECTED; 
	}

	
	/* connect to the server */
	int sd = socket(AF_INET , SOCK_STREAM | SOCK_NONBLOCK , 0);
	if (sd < 0)
		return -1;

	
	struct timeval t;
	settime(&t , 20 , 0);
	status = joera_connect (sd , &t);
	if (status) {
		close(sd);
		joera_listener.isconnected = false;
		pthread_mutex_unlock(&(joera_listener.mutex));
		return status;	
	}	

	printf("Connected to the server\n");
	joera_listener.sd = sd;
	joera_listener.isconnected = true;
	
	
	/* send set listener request */
	struct joera_req_msg req;
	req.msg.type = J_REQ_SETLISTENER;
	req.appid = appid;
	req.msg.len = 0;
	strncpy(req.sessionid , sessionid , SESSIONID_LEN);
	
	/* encode header */
	uint8_t reqhdr_buf[REQMSGSIZE]; /* request header buffer */
	encode_request_header(&req , reqhdr_buf);
	
	/* send header */
	settime (&t , 20 , 0);
	status =  joera_send(sd, reqhdr_buf , REQMSGSIZE , &t);
	if (status) {
		close(sd);
		joera_listener.isconnected = false;
		pthread_mutex_unlock(&(joera_listener.mutex));
		return status;	
	}
	
	printf("Header Sent...\n");
        /* receive response header */
	struct joera_res_msg res;
	settime(&t , 20 , 0);
	uint8_t reshdr_buf[RESMSGSIZE]; /* response header buffer */
	status = joera_recv(sd , reshdr_buf , RESMSGSIZE , &t);
	if (status) {
		close(sd);
		joera_listener.isconnected = false;
		pthread_mutex_unlock(&(joera_listener.mutex));
		return status;	
	}

	printf("Header received...\n");
	decode_response_header(&res , reshdr_buf);
	
	if (res.msg.type != J_RES_SETLISTENER ||
		res.res != J_NOERROR){
		close(sd);
		joera_listener.isconnected = false;
	}

	
	pthread_mutex_unlock(&(joera_listener.mutex));

	if (joera_listener.isconnected)
		pthread_cond_broadcast(&(joera_listener.cond));
       
	return res.res;
}
