%%--------------------------------------------------------------------
%% Copyright (c) 2020 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------
-module(emqx_auth_aliyun_iot).

-include("emqx_auth_aliyun_iot.hrl").

-export([ register_metrics/0
        , check/3
        , description/0
        ]).

-spec(register_metrics() -> ok).
register_metrics() ->
    lists:foreach(fun emqx_metrics:ensure/1, ?AUTH_METRICS).

check(ClientInfo, AuthResult,
      #{auth_cmd  := AuthCmd,
        super_cmd := SuperCmd,
        timeout   := Timeout,
        type      := Type,
        pool      := Pool}) ->
    CheckPass = case emqx_auth_aliyun_iot_cli:q(Pool, Type, AuthCmd, ClientInfo, Timeout) of
                  {ok, DeviceSecret} when is_binary(DeviceSecret) ->
                    check_pass(DeviceSecret, ClientInfo);
                  {ok, [undefined | _]} ->
                    {error, not_found};
                  {ok, [DeviceSecret]} ->
                    check_pass(DeviceSecret, ClientInfo);
                  {error, Reason} ->
                        logger:error("[Redis] Command: ~p failed: ~p", [AuthCmd, Reason]),
                        {error, not_found}
                end,
    case CheckPass of
        ok ->
            ok = emqx_metrics:inc(?AUTH_METRICS(success)),
            IsSuperuser = is_superuser(Pool, Type, SuperCmd, ClientInfo, Timeout),
            {stop, AuthResult#{is_superuser => IsSuperuser,
                               anonymous    => false,
                               auth_result  => success}};
        {error, not_found} ->
            ok = emqx_metrics:inc(?AUTH_METRICS(ignore));
        {error, ResultCode} ->
            ok = emqx_metrics:inc(?AUTH_METRICS(failure)),
            logger:error("[Redis] Auth from redis failed: ~p", [ResultCode]),
            {stop, AuthResult#{auth_result => ResultCode, anonymous => false}}
    end.

description() -> "Authentication with Redis".

-spec(is_superuser(atom(), atom(), undefined|list(), emqx_types:client(), timeout()) -> boolean()).
is_superuser(_Pool, _Type, undefined, _ClientInfo, _Timeout) -> false;
is_superuser(Pool, Type, SuperCmd, ClientInfo, Timeout) ->
    case emqx_auth_aliyun_iot_cli:q(Pool, Type, SuperCmd, ClientInfo, Timeout) of
        {ok, undefined} -> false;
        {ok, <<"1">>}   -> true;
        {ok, _Other}    -> false;
        {error, _Error} -> false
    end.

check_pass(DeviceSecret, #{clientid := ClientId, username := Username, password := Password}) ->
  PasswordResult = emqx_auth_aliyun_iot_util:gen_password(to_str(ClientId), to_str(Username), to_str(DeviceSecret)),
  case string:to_lower(to_str(Password)) =:= string:to_lower(PasswordResult) of
    true -> ok;
    false -> {error, not_authorized}
  end.

-spec to_str(binary()) -> string().
to_str(Param) ->
  lists:flatten(binary_to_list(Param)).

