module.exports = function( config , dependencies )
{
	let module = { };
		
	module._crypto = function( )
	{ 
		return dependencies.crypto;
	}
	
	module._sign = function( signStr )
	{
		return this._crypto( ).createHmac( 'sha256' , config.secretKey ).
				update( signStr , 'utf8' ).digest( 'hex' ).toUpperCase( );
	};
	
	module.call = function( uri , method , token , payload , sigHeaders )
	{
		let stringPayload = ( payload ) ? JSON.stringify( payload ) : '';
		let timestamp = Date.now( ).toString( );
		let contentHash = this._crypto( ).createHash( 'sha256' ).update( stringPayload ).digest('hex');
		let stringToSign = [ method , contentHash , '' , uri ].join( '\n' );
		let signStr = config.accessKey + token + timestamp + stringToSign;
		let sign = this._sign( signStr );
		var headers =
		{
			't': timestamp ,
			'sign_method': 'HMAC-SHA256' ,
			'Accept': 'Accept: application/json, text/plan' ,
			'client_id': config.accessKey ,
			'User-Agent': 'tuyacloudnodejs' ,
			'Content-Length': payload.length ,
			'sign': sign
		};
		if ( token )
		{
			headers.access_token = token;
		}
		let obj = 
		{
			headers: headers ,
			uri: config.server + uri ,
			method: method ,
			body: payload ,
			json: true
		};
		return new Promise( function( resolve , reject ) 
		{
			dependencies.requestsHandler( obj , function ( error , res , body ) 
			{
				if ( !error && res.statusCode == 200 ) 
				{
					resolve( body );
				} 
				else 
				{
					resolve( { "code": res.statusCode , "data": res.body , "error": error } );
					//reject( error );
				}
			} );
		} );
	};

	return module;
};