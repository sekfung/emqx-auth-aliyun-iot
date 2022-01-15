%%%-------------------------------------------------------------------
%%% @author sekfung
%%% @copyright (C) 2022, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 09. 1月 2022 5:16 PM
%%%-------------------------------------------------------------------
-module(emqx_auth_aliyun_iot_util).
-author("sekfung").

%% API
-export([gen_password/3]).

-spec gen_password(string(), string(), string()) -> {ok, string()}.
gen_password(ClientId, UserName, DeviceSecret) ->
  try
    {ok, ParamMap} = check_and_split_param(ClientId, UserName, DeviceSecret),
    {ok, StrToSign} = build_str_to_sign(ParamMap),
    {ok, Password} = sign(ParamMap, DeviceSecret, StrToSign),
    Password
  catch
    error:{badmatch, Error} -> Error;
    error:_ -> {error, invalid_param}
  end.



-spec hmac_sha1_sign(string(), string()) -> string().
hmac_sha1_sign(DeviceSecret, StrToSign) ->
  <<Mac:160/integer>> = crypto:hmac(sha, list_to_binary(DeviceSecret), list_to_binary(StrToSign)),
  string:to_lower(lists:flatten(integer_to_list(Mac, 16))).

check_and_split_param(ClientId, UserName, DeviceSecret) ->
  try
    {ok, ClientIdResult} = check_input(ClientId, UserName, DeviceSecret),
    ClientIdResult = string:tokens(ClientId, "|"),
    %% device ID, not mqtt client id
    DeviceId = lists:nth(1, ClientIdResult),
    {ok, DeviceName, ProductKey} = check_deviceName_productKey(UserName),
    {ok, ExtraParams} = check_extra_param(ClientIdResult),
    DeviceMap = #{"deviceid" => DeviceId, "devicename" => DeviceName, "productkey" => ProductKey},
    {ok, convert_param_to_map(length(ExtraParams), ExtraParams, DeviceMap)}
  catch
    error:{badmatch, Error} -> Error;
    error:_ -> {error, invalid_param}
  end.

sign(ParamMaps, DeviceSecret, StrToSign) ->
  %% check if exist timestamp
  SignMethod = maps:get("signmethod", ParamMaps, "hmacsha1"),
  case string:equal(SignMethod, "hmacsha1") of
    true -> {ok, hmac_sha1_sign(DeviceSecret, lists:flatten(StrToSign))};
    _ -> {error, unsupported_sign_method}
  end.

build_str_to_sign(ParamMaps) ->
  StrToSign = case maps:is_key("timestamp", ParamMaps) of
    false ->
      io_lib:format("clientId~sdeviceName~sproductKey~s", [maps:get("deviceid", ParamMaps), maps:get("devicename", ParamMaps), maps:get("productkey", ParamMaps)]);
    true ->
      TimeStamp = maps:get("timestamp", ParamMaps),
      io_lib:format("clientId~sdeviceName~sproductKey~stimestamp~s", [maps:get("deviceid", ParamMaps), maps:get("devicename", ParamMaps), maps:get("productkey", ParamMaps), TimeStamp])
  end,
  {ok , StrToSign}.

check_extra_param(ClientIdResult) ->
  ExtraParams = string:tokens(lists:nth(2, ClientIdResult), ","),
  if
    erlang:length(ExtraParams) < 2 -> {error, invalid_param};
    true -> {ok, ExtraParams}
  end.

check_input(ClientId, UserName, DeviceSecret) ->
  ClientIdResult = string:tokens(ClientId, "|"),
  if
    ClientId =:= "" -> {error, invalid_param};
    erlang:length(ClientIdResult) =< 1 -> {error, invalid_param};
    UserName =:= "" -> {error, invalid_param};
    DeviceSecret =:= "" -> {error, invalid_param};
    true -> {ok, ClientIdResult}
  end.

check_deviceName_productKey(UserName) ->
  %% spilt device name and product key from mqtt username
  DeviceNameAndProductKey = string:tokens(UserName, "&"),
  case erlang:length(DeviceNameAndProductKey) =< 1 of
    true -> {error, invalid_param};
    false ->
      DeviceName = lists:nth(1, DeviceNameAndProductKey),
      ProductKey = lists:nth(2, DeviceNameAndProductKey),
      {ok, DeviceName, ProductKey}
  end.


convert_param_to_map(0, _, Props) ->
  Props;

convert_param_to_map(N, Term, Props) when N > 0 ->
  PropsStr = lists:nth(N, Term),
  Key = lists:nth(1, string:tokens(PropsStr, "=")),
  Value = lists:nth(2, string:tokens(PropsStr, "=")),
  convert_param_to_map(N - 1, Term, maps:put(Key, Value, Props)).
