<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Requests\ForgotPasswordRequest; // 🆕 NEW
use App\Http\Requests\ResetPasswordRequest;   // 🆕 NEW
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Password; // 🆕 NEW: For password broker
use OpenApi\Annotations as OA; // Required for OA annotations
use Illuminate\Auth\Events\Verified;

class AuthController extends Controller
{
    /**
     * @OA\Post(
     *      path="/register",
     *      operationId="registerUser",
     *      tags={"Authentication"},
     *      summary="Register a new user",
     *      description="Creates a new user account and returns a user object and an access token.",
     *      @OA\RequestBody(
     *          required=true,
     *          description="User registration data",
     *          @OA\JsonContent(
     *              required={"fullname","email","password","password_confirmation","datebirthday","gender"},
     *              @OA\Property(property="fullname", type="string", example="John Doe"),
     *              @OA\Property(property="email", type="string", format="email", example="john.doe@example.com"),
     *              @OA\Property(property="password", type="string", format="password", example="password123", minLength=8),
     *              @OA\Property(property="password_confirmation", type="string", format="password", example="password123", minLength=8),
     *              @OA\Property(property="datebirthday", type="string", format="date", example="1990-01-01"),
     *              @OA\Property(property="gender", type="string", enum={"male", "female", "other"}, example="male"),
     *              @OA\Property(property="linkphoto", type="string", format="url", nullable=true, example="http://example.com/photo.jpg")
     *          )
     *      ),
     *      @OA\Response(
     *          response=201,
     *          description="User registered successfully",
     *          @OA\JsonContent(
     *              @OA\Property(property="message", type="string", example="User registered successfully"),
     *              @OA\Property(property="access_token", type="string", example="1|abcdef123456"),
     *              @OA\Property(property="token_type", type="string", example="Bearer"),
     *              @OA\Property(property="user", ref="#/components/schemas/User")
     *          )
     *      ),
     *      @OA\Response(response=422, description="Validation error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'fullname' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users,email', // Ensure email is unique in the 'users' table
            'password' => 'required|string|min:8|confirmed',
            'datebirthday' => 'required|date',
            'gender' => ['required', 'string', Rule::in(['male', 'female', 'other'])], // Adjust as per your gender options
            // 'role' => ['required', 'string', Rule::in(['user', 'admin', 'editor'])], // Role is now defaulted, not user-settable at registration
            'linkphoto' => 'nullable|string|url|max:255',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::create([
            'fullname' => $request->fullname,
            'email' => $request->email,
            'password' => $request->password, // The 'hashed' cast in User model handles hashing
            'datebirthday' => $request->datebirthday,
            'gender' => $request->gender,
            'role' => 'user', // Default role to 'user'
            'linkphoto' => $request->linkphoto,
        ]);

        // Send email verification notification if user implements MustVerifyEmail
        if ($user instanceof \Illuminate\Contracts\Auth\MustVerifyEmail && ! $user->hasVerifiedEmail()) {
            $user->sendEmailVerificationNotification();
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'message' => 'User registered successfully',
            'access_token' => $token,
            'token_type' => 'Bearer',
            'user' => $user,
        ], 201);
    }

    /**
     * @OA\Post(
     *      path="/login",
     *      operationId="loginUser",
     *      tags={"Authentication"},
     *      summary="Log in an existing user",
     *      description="Logs in a user and returns an access token and user details.",
     *      @OA\RequestBody(
     *          required=true,
     *          description="User login credentials",
     *          @OA\JsonContent(
     *              required={"email","password"},
     *              @OA\Property(property="email", type="string", format="email", example="john.doe@example.com"),
     *              @OA\Property(property="password", type="string", format="password", example="password123")
     *          )
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="User logged in successfully",
     *          @OA\JsonContent(
     *              @OA\Property(property="message", type="string", example="User logged in successfully"),
     *              @OA\Property(property="access_token", type="string", example="2|abcdef123456"),
     *              @OA\Property(property="token_type", type="string", example="Bearer"),
     *              @OA\Property(property="user", ref="#/components/schemas/User")
     *          )
     *      ),
     *      @OA\Response(response=401, description="Invalid login details", @OA\JsonContent(@OA\Property(property="message", type="string", example="Invalid login details"))),
     *      @OA\Response(response=422, description="Validation error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json(['message' => 'Invalid login details'], 401);
        }

        /** @var \App\Models\User $user */
        $user = Auth::user(); // After successful attempt, Auth::user() returns the authenticated user.

        // $user = User::where('email', $request['email'])->firstOrFail(); // This is redundant after Auth::attempt

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'message' => 'User logged in successfully',
            'access_token' => $token,
            'token_type' => 'Bearer',
            'user' => $user,
        ]);
    }

    /**
     * @OA\Post(
     *      path="/logout",
     *      operationId="logoutUser",
     *      tags={"Authentication"},
     *      summary="Log out the current user",
     *      description="Invalidates the current user's access token.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Response(
     *          response=200,
     *          description="Successfully logged out",
     *          @OA\JsonContent(@OA\Property(property="message", type="string", example="Successfully logged out"))
     *      ),
     *      @OA\Response(response=401, description="Unauthenticated", @OA\JsonContent(@OA\Property(property="message", type="string", example="Unauthenticated.")))
     * )
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * @OA\Get(
     *      path="/user",
     *      operationId="getAuthenticatedUser",
     *      tags={"Users"},
     *      summary="Get the authenticated user's details",
     *      description="Returns the details of the currently authenticated user.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Response(
     *          response=200, description="Successful operation", @OA\JsonContent(ref="#/components/schemas/User")
     *      ),
     *      @OA\Response(response=401, description="Unauthenticated", @OA\JsonContent(@OA\Property(property="message", type="string", example="Unauthenticated.")))
     * )
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function user(Request $request)
    {
        return response()->json($request->user());
    }

    /**
     * @OA\Post(
     *      path="/email/resend-verification",
     *      operationId="resendVerificationEmail",
     *      tags={"Authentication"},
     *      summary="Resend email verification notification",
     *      description="Resends the email verification link to the authenticated user if their email is not yet verified.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Response(response=200, description="Verification link sent.", @OA\JsonContent(@OA\Property(property="message", type="string", example="Verification link sent."))),
     *      @OA\Response(response=400, description="Email already verified.", @OA\JsonContent(@OA\Property(property="message", type="string", example="Email already verified."))),
     *      @OA\Response(response=401, description="Unauthenticated")
     * )
     */
    public function resendEmailVerification(Request $request)
    {
        if ($request->user()->hasVerifiedEmail()) {
            return response()->json(['message' => 'Email already verified.'], 400);
        }

        $request->user()->sendEmailVerificationNotification();

        return response()->json(['message' => 'Verification link sent.']);
    }

    // Note: The actual email verification happens when the user clicks the link
    // in their email. That link typically points to a route like `verification.verify`
    // (e.g., /email/verify/{id}/{hash}?expires={expires}&signature={signature})
    // which Laravel handles to update the `email_verified_at` field.

    /**
     * @OA\Get(
     *      path="/email/verify/{id}/{hash}",
     *      operationId="verifyEmailAddress",
     *      tags={"Authentication"},
     *      summary="Verify user's email address",
     *      description="Verifies the user's email address using the ID and hash from the verification link. This endpoint is typically accessed by clicking a link from an email.",
     *      @OA\Parameter(name="id", in="path", description="User ID (UUID)", required=true, @OA\Schema(type="string", format="uuid")),
     *      @OA\Parameter(name="hash", in="path", description="Verification hash", required=true, @OA\Schema(type="string")),
     *      @OA\Parameter(name="expires", in="query", description="Expiration timestamp for the signed URL", required=true, @OA\Schema(type="integer")),
     *      @OA\Parameter(name="signature", in="query", description="Signature for the signed URL", required=true, @OA\Schema(type="string")),
     *      @OA\Response(response=200, description="Email successfully verified.", @OA\JsonContent(@OA\Property(property="message", type="string", example="Email address successfully verified."))),
     *      @OA\Response(response=202, description="Email already verified.", @OA\JsonContent(@OA\Property(property="message", type="string", example="Email address already verified."))),
     *      @OA\Response(response=400, description="Invalid verification link or hash mismatch."),
     *      @OA\Response(response=403, description="Invalid or expired verification link (signature validation failed)."),
     *      @OA\Response(response=404, description="User not found for verification.")
     * )
     */
    public function verifyEmail(Request $request, $id, $hash)
    {
        // The 'signed' middleware (applied in routes/api.php) handles signature and expiration validation.
        // If the signature is invalid or expired, a 403 response is typically returned by the middleware.

        $user = User::find($id); // Find user by primary key (iduser)

        if (!$user) {
            return response()->json(['message' => 'User not found for verification.'], 404);
        }

        // Verify the hash. This ensures the link is for this specific user's email.
        if (!hash_equals((string) $hash, sha1($user->getEmailForVerification()))) {
            return response()->json(['message' => 'Invalid verification link or hash mismatch.'], 400);
        }

        if ($user->hasVerifiedEmail()) {
            return response()->json(['message' => 'Email address already verified.'], 202); // 202 Accepted or 200 OK
        }

        if ($user->markEmailAsVerified()) {
            event(new Verified($user)); // Dispatch the Verified event
        }

        return response()->json(['message' => 'Email address successfully verified.']);
    }

    /**
     * @OA\Post(
     *      path="/forgot-password",
     *      operationId="sendPasswordResetLink",
     *      tags={"Authentication"},
     *      summary="Send password reset link",
     *      description="Sends a password reset link to the user's email address if the email exists in the system.",
     *      @OA\RequestBody(
     *          required=true,
     *          description="User's email to send reset link",
     *          @OA\JsonContent(
     *              required={"email"},
     *              @OA\Property(property="email", type="string", format="email", example="user@example.com")
     *          )
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Password reset link sent successfully (if email exists).",
     *          @OA\JsonContent(@OA\Property(property="message", type="string", example="Password reset link sent. Please check your email."))
     *      ),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError")),
     *      @OA\Response(response=404, description="User not found (though typically a generic success message is returned for security).")
     * )
     */
    public function forgotPassword(ForgotPasswordRequest $request)
    {
        $validatedData = $request->validated();

        // Use Laravel's built-in password broker to send the reset link
        $status = Password::sendResetLink($validatedData);

        if ($status === Password::RESET_LINK_SENT) {
            return response()->json(['message' => Password::RESET_LINK_SENT]);
        }

        // If the status is INVALID_USER, it means the email was not found.
        // For security, you might still want to return a generic success message.
        // However, returning the actual status can be helpful for debugging or specific frontend handling.
        // Let's return the status directly for now.
        // If $status is Password::RESET_THROTTLED, it means the user requested too many resets recently.
        return response()->json(['message' => $status], $status === Password::INVALID_USER ? 404 : 422);
    }

    /**
     * @OA\Post(
     *      path="/reset-password",
     *      operationId="resetUserPassword",
     *      tags={"Authentication"},
     *      summary="Reset user's password",
     *      description="Resets the user's password using the token from the password reset link.",
     *      @OA\RequestBody(
     *          required=true,
     *          description="Password reset data",
     *          @OA\JsonContent(
     *              required={"token", "email", "password", "password_confirmation"},
     *              @OA\Property(property="token", type="string", example="verylongresettokenstring", description="The password reset token from the email link."),
     *              @OA\Property(property="email", type="string", format="email", example="user@example.com", description="User's email address."),
     *              @OA\Property(property="password", type="string", format="password", minLength=8, example="newSecurePassword123", description="New password."),
     *              @OA\Property(property="password_confirmation", type="string", format="password", minLength=8, example="newSecurePassword123", description="Confirmation of the new password.")
     *          )
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Password reset successfully.",
     *          @OA\JsonContent(@OA\Property(property="message", type="string", example="Password has been reset successfully."))
     *      ),
     *      @OA\Response(response=422, description="Validation Error or Invalid Token/Email", @OA\JsonContent(ref="#/components/schemas/ValidationError")),
     *      @OA\Response(response=400, description="Invalid token or email.", @OA\JsonContent(@OA\Property(property="message", type="string")))
     * )
     */
    public function resetPassword(ResetPasswordRequest $request)
    {
        $validatedData = $request->validated();

        // Use Laravel's built-in password broker to reset the password
        $status = Password::reset(
            $validatedData, // This includes email, password, password_confirmation, token
            function (User $user, string $password) {
                $user->password = $password; // Hashing is handled by the User model's mutator
                $user->save();
                // Optionally, you can dispatch an event here: event(new PasswordReset($user));
                // And invalidate all tokens for security
                $user->tokens()->delete();
            }
        );

        if ($status === Password::PASSWORD_RESET) {
            return response()->json(['message' => $status]);
        }

        // Handle errors like invalid token or user
        return response()->json(['message' => $status], 400);
    }
}
