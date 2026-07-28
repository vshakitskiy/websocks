-module(websocks_ffi).

-export([is_utf8/1, to_string/1, inflate_limited/3]).

to_string(Payload) ->
    case is_utf8(Payload) of
        true -> {ok, Payload};
        false -> {error, nil}
    end.

is_utf8(Payload) when is_binary(Payload) ->
    case skip_ascii(Payload) of
        <<>> -> true;
        Rest -> is_binary(unicode:characters_to_binary(Rest, utf8))
    end;
is_utf8(_Payload) ->
    false.

-define(HIGH_BITS, 16#80808080808080).

skip_ascii(<<A:56, B:56, C:56, D:56, Rest/binary>>) when
    A band ?HIGH_BITS =:= 0,
    B band ?HIGH_BITS =:= 0,
    C band ?HIGH_BITS =:= 0,
    D band ?HIGH_BITS =:= 0
->
    skip_ascii(Rest);
skip_ascii(<<Word:56, Rest/binary>>) when Word band ?HIGH_BITS =:= 0 ->
    skip_ascii(Rest);
skip_ascii(<<Word:48>>) when Word band 16#808080808080 =:= 0 -> <<>>;
skip_ascii(<<Word:40>>) when Word band 16#8080808080 =:= 0 -> <<>>;
skip_ascii(<<Word:32>>) when Word band 16#80808080 =:= 0 -> <<>>;
skip_ascii(<<Word:24>>) when Word band 16#808080 =:= 0 -> <<>>;
skip_ascii(<<Word:16>>) when Word band 16#8080 =:= 0 -> <<>>;
skip_ascii(<<Word:8>>) when Word band 16#80 =:= 0 -> <<>>;
skip_ascii(Rest) ->
    Rest.

inflate_limited(Context, Data, Limit) ->
    try
        inflate_loop(zlib:safeInflate(Context, Data), Context, Limit, 0, [])
    catch
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
