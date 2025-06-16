<?php

use App\Http\Controllers\Api\AuthController;  // Corrected namespace if it was wrong before
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\Api\ArticleController; // Ensure this is the correct controller
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

// Publicly accessible route to get all articles
Route::get('/articles', [ArticleController::class, 'index'])->name('articles.index.public');
// Publicly accessible route to get a single article by ID
Route::get('/articles/{id}', [ArticleController::class, 'show'])->name('articles.show.public')->where('id', '[0-9]+');

// Email Verification Route (must be publicly accessible but signed)
Route::get('/email/verify/{id}/{hash}', [AuthController::class, 'verifyEmail'])
    ->name('verification.verify')
    ->middleware(['signed']) // Ensures the URL hasn't been tampered with and isn't expired
    ->where('id', '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') // UUID constraint for user ID
    ->where('hash', '[0-9a-fA-F]{40}'); // SHA1 hash constraint

// Protected routes - require authentication
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/user', [AuthController::class, 'user']);
    Route::post('/email/resend-verification', [AuthController::class, 'resendEmailVerification'])->name('verification.send');
    // Article routes requiring authentication (create, update, delete, show individual)
    // We exclude 'index' and 'show' as they are now public.
    // We specify 'id' as the parameter name to match the controller methods.
    Route::apiResource('articles', ArticleController::class)->except(['index', 'show'])->parameters(['articles' => 'id']);

    // User Management Routes (excluding create, as registration is handled by AuthController)
    Route::get('/users', [UserController::class, 'index']);
    Route::get('/users/{user_id}', [UserController::class, 'show'])->where('user_id', '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'); // UUID constraint
    Route::put('/users/{user_id}', [UserController::class, 'update'])->where('user_id', '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}');
    Route::delete('/users/{user_id}', [UserController::class, 'destroy'])->where('user_id', '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}');
});
