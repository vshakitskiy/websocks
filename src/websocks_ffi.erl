-module(websocks_ffi).

-export([is_utf8/1, to_string/1, inflate_limited/3]).

%% Gleam strings are UTF-8 binaries on Erlang, so validating a payload is all the
%% conversion a valid one needs. `bit_array.to_string` would re-validate through
%% the stdlib's per-codepoint loop.
to_string(Payload) ->
    case is_utf8(Payload) of
        true -> {ok, Payload};
        false -> {error, nil}
    end.

is_utf8(Payload) when is_binary(Payload) ->
    unicode:bin_is_7bit(Payload)
        orelse is_binary(unicode:characters_to_binary(Payload, utf8, utf8));
is_utf8(_Payload) ->
    false.

%% `zlib:inflate/2` decompresses in one shot with no cap, so a small frame can
%% expand into an arbitrarily large binary. `zlib:safeInflate/2` yields chunk by
%% chunk instead, letting the running total be checked against `Limit` and the
%% work abandoned as soon as it is exceeded.
inflate_limited(Context, Data, Limit) ->
    try
        inflate_loop(zlib:safeInflate(Context, Data), Context, Limit, 0, [])
    catch
        %% malformed deflate stream
        error:_Reason -> {error, nil}
    end.

inflate_loop({Status, Output}, Context, Limit, Size, Acc) ->
    Grown = Size + iolist_size(Output),
    Chunks = [Output | Acc],
    if
        Grown > Limit ->
            {error, nil};
        Status =:= finished ->
            {ok, iolist_to_binary(lists:reverse(Chunks))};
        true ->
            inflate_loop(
                zlib:safeInflate(Context, <<>>), Context, Limit, Grown, Chunks
            )
    end.
