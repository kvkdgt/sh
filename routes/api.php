<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::post('/auth/signup', [App\Http\Controllers\AuthController::class, 'Signup']);
Route::post('/auth/login', [App\Http\Controllers\AuthController::class, 'SignIn']);
Route::get('/auth/logout', [App\Http\Controllers\AuthController::class, 'SignOut']);
Route::post('/auth/changepassword', [App\Http\Controllers\AuthController::class, 'ChangePassword']);



