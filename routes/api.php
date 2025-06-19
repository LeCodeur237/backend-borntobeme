<?php

use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\UserController;
use App\Http\Controllers\API\ContactController; // Import the new controller
use App\Http\Controllers\API\CommentsController;
use App\Http\Controllers\API\ArticlesController;
use Illuminate\Http\Request;
use App\Http\Controllers\API\UserInfoController;
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

Route::post('/register', [AuthController::class, 'register'])->name('register');

// Public endpoint for contact form
Route::post('/contact', [ContactController::class, 'send']);
Route::post('/login', [AuthController::class, 'login'])->name('login');

// Password Reset Routes
Route::post('/forgot-password', [AuthController::class, 'forgotPassword'])->name('password.email'); // Matches Laravel's naming convention
Route::post('/reset-password', [AuthController::class, 'resetPassword'])->name('password.update'); // Matches Laravel's naming convention


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

    // User Management Routes (excluding create, as registration is handled by AuthController)
    Route::prefix('users')->group(function () {

        // Get all users (Admin only)
        Route::get('/', [UserController::class, 'index']);

        // Get specific user
        Route::get('/{user}', [UserController::class, 'show'])
            ->where('user', '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}');

        // 🆕 NEW: Update user profile (fullname, gender, birthday, bio, preferences only)
        Route::put('/{user}/profile', [UserController::class, 'updateProfile'])
            ->where('user', '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}');

        // 🆕 NEW: Change user password
        Route::put('/{user}/password', [UserController::class, 'changePassword'])
            ->where('user', '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}');

        // Delete user (Admin only)
        Route::delete('/{user}', [UserController::class, 'destroy'])
            ->where('user', '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}');

        // User Info routes (using route model binding for User)
        Route::get('/{user}/info', [UserInfoController::class, 'show']);
        Route::match(['post', 'put'], '/{user}/info', [UserInfoController::class, 'storeOrUpdate']);
    });

    // User Info routes (using route model binding for User)
    // The {user} parameter will automatically resolve to a User model instance
    Route::get('/users/{user}/info', [UserInfoController::class, 'show']);
    Route::match(['post', 'put'], '/users/{user}/info', [UserInfoController::class, 'storeOrUpdate']);


    // Article Management Routes (Create, Update, Delete require authentication)
    Route::post('/articles', [ArticlesController::class, 'store']);
    Route::put('/articles/{article}', [ArticlesController::class, 'update'])->where('article', '[0-9]+');
    Route::delete('/articles/{article}', [ArticlesController::class, 'destroy'])->where('article', '[0-9]+');

    // Comment Management Routes (Create, Update, Delete require authentication)
    // Comments are typically nested under articles for creation
    Route::post('/articles/{article}/comments', [CommentsController::class, 'store'])->where('article', '[0-9]+');
    Route::put('/comments/{comment}', [CommentsController::class, 'update'])->where('comment', '[0-9]+');
    Route::delete('/comments/{comment}', [CommentsController::class, 'destroy'])->where('comment', '[0-9]+');
});

// Public Article Routes (Index, Show)
Route::get('/articles', [ArticlesController::class, 'index']);
Route::get('/articles/{article}', [ArticlesController::class, 'show'])->where('article', '[0-9]+');

// Public Comment Routes (List comments for an article)
Route::get('/articles/{article}/comments', [CommentsController::class, 'index'])->where('article', '[0-9]+');
