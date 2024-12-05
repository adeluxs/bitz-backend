<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthenticationController;

// Route::middleware(['auth:sanctum'])->get('/user', function (Request $request) {
//     return $request->user();
// });


Route::post('register', [AuthenticationController::class, 'register']);
Route::post('login', [AuthenticationController::class, 'login']);
Route::post('logout', [AuthenticationController::class, 'logout']);
Route::get('user', [AuthenticationController::class, 'loginUser']);

// Google Auth routes
// Route::get('auth/google', [AuthenticationController::class, 'redirectToGoogle']);
// Route::get('auth/google/callback', [AuthenticationController::class, 'handleGoogleCallback']);

// Google Auth routes
Route::get('auth/google', [AuthenticationController::class, 'redirectToGoogle'])->name('user.google');
Route::post('auth/google/callback', [AuthenticationController::class, 'handleGoogleCallback']);

