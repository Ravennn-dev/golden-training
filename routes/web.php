<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/test-1', function () {
    return response()->json(['test1']);
});

Route::get('/test-2', function () {
    return response()->json(['test2']);
});

Route::get('/test-3', function () {
    return response()->json(['test3']);
});
