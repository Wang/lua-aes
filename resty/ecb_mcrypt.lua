--[[
	12:24 2015/9/30	  lilien

]]
local ffi = require 'ffi'
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_copy = ffi.copy
local setmetatable = setmetatable
local _M = { }
local mt = { __index = _M }

 ffi.cdef[[
struct CRYPT_STREAM;
typedef struct CRYPT_STREAM *MCRYPT;

MCRYPT mcrypt_module_open(char *algorithm,
                          char *a_directory, char *mode,
                          char *m_directory);

int mcrypt_generic_init(const MCRYPT td, void *key, int lenofkey,
                        void *IV);
void free(void *ptr);
void mcrypt_free(void *ptr);

int mcrypt_enc_get_key_size(const MCRYPT td);
int mcrypt_enc_get_supported_key_sizes(const MCRYPT td, int* len);

int mcrypt_generic_deinit(const MCRYPT td);
int mcrypt_generic_end(const MCRYPT td);
int mdecrypt_generic(MCRYPT td, void *plaintext, int len);
int mcrypt_generic(MCRYPT td, void *plaintext, int len);
int mcrypt_module_close(MCRYPT td);
int mcrypt_enc_mode_has_iv(MCRYPT td);
int mcrypt_enc_get_iv_size(MCRYPT td);
int mcrypt_enc_is_block_mode(MCRYPT td);
int mcrypt_enc_get_block_size(MCRYPT td);
]]

local mcrypt = ffi.load("libmcrypt")

_M.new = function (self, key)
    local cipher = 'rijndael-128'
    local mode = 'ecb'

    local c_cipher 	=	ffi_new("char[?]",#cipher+1, cipher)
    local c_mode 	=	ffi_new("char[4]", mode)

    local td = mcrypt.mcrypt_module_open(c_cipher, nil, c_mode, nil)
	if  td ==0  then
		ngx.log(ngx.ERR , "mcrypt_module_open failed")
		return nil
	end

	local max_key_length = mcrypt.mcrypt_enc_get_key_size(td);
	if  #(key) > max_key_length  then
		ngx.log(ngx.ERR , "Size of key is too large for this algorithm key_len:",key_len,",max_key:",max_key_length)
		return nil
	end
	local key_sizes = {16, 24, 32}
	local use_key_length = max_key_length
	for  k in ipairs(key_sizes) do
		if key_sizes[k] >= #(key) then
			use_key_length = key_sizes[k]
			break
		end
	end
	local key_s = ffi_new("char[?]",use_key_length)
	ffi.copy(key_s ,key, math.min(#(key), use_key_length));

	local block = mcrypt.mcrypt_enc_is_block_mode(td);
	local block_size = nil
	if  block == 1 then
		block_size =	mcrypt.mcrypt_enc_get_block_size(td);
	end

	local ini_ret = mcrypt.mcrypt_generic_init(td, key_s, use_key_length, nil)
	if ini_ret < 0 then
		ngx.log(ngx.ERR , "Mcrypt initialisation failed");
		ngx.say(  ini_ret,"ini_ret initialisation failed");
		return nil
	end
	mcrypt.mcrypt_generic_deinit(td)
	mcrypt.mcrypt_module_close(td)

    return setmetatable( { 
		_key = key,
		_key_chars = key_s,
		_key_len = use_key_length,
		_block_size = block_size,
		_cipher = c_cipher,
		_mode = c_mode
		 }, mt )
end


_M.pass = function (self, raw,enc_or_dec)
	local dencrypt	= enc_or_dec
	local data_len, data_size = #raw;

	if  self._block_size ~= nil then
		data_size = math.floor(((data_len - 1) / self._block_size) + 1) * self._block_size;
	end

	local data_s = ffi_new("char[?]",data_size)
	ffi.fill(data_s ,data_size,0);
	ffi.copy(data_s ,raw ,data_len);

    local td = mcrypt.mcrypt_module_open(self._cipher, nil, self._mode, nil)
	if  td == 0  then
		ngx.log(ngx.ERR , "mcrypt_module_open failed")
		return nil
	end
	local ini_ret = mcrypt.mcrypt_generic_init(td, self._key_chars, self._key_len, nil)
	if ini_ret < 0 then
		ngx.log(ngx.ERR , "Mcrypt initialisation failed");
		return nil
	end

	if  dencrypt == 1 then
		mcrypt.mcrypt_generic(td, data_s, data_size);
	else
		mcrypt.mdecrypt_generic(td, data_s, data_size);
	end
	mcrypt.mcrypt_generic_deinit(td)
	mcrypt.mcrypt_module_close(td)

	local pad_size = 0
	for i=data_size-1, 0, -1 do
		if data_s[i] == 0 then
			pad_size = pad_size + 1
		else
			break
		end
	end
	local ret_str = ffi_str(data_s,data_size - pad_size);

	return ret_str
end

_M.encrypt = function (self, raw)
	return _M.pass(self, raw, 1);
end

_M.decrypt = function(self, raw)
	return _M.pass(self, raw, 0);
end

return _M