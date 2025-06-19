<?php

// ============================================
// UserController.php - Version mise à jour
// ============================================

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Requests\UpdateUserProfileRequest;
use App\Http\Requests\ChangePasswordRequest;
use App\Models\UserInfo;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use OpenApi\Annotations as OA;

class UserController extends Controller
{
    /**
     * @OA\Get(
     *      path="/users",
     *      operationId="getUsersList",
     *      tags={"Users"},
     *      summary="Get list of users (Admin only)",
     *      description="Returns a paginated list of users. This endpoint is restricted to administrators.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(name="page", in="query", description="Page number", required=false, @OA\Schema(type="integer")),
     *      @OA\Response(
     *          response=200,
     *          description="Successful operation",
     *          @OA\JsonContent(type="array", @OA\Items(ref="#/components/schemas/User"))
     *      ),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Admin access required")
     * )
     */
    public function index()
    {
        if (Auth::user()->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. Admin access required.'], 403);
        }
        $users = User::paginate(15);
        return response()->json($users);
    }

    /**
     * @OA\Get(
     *      path="/users/{user_id}",
     *      operationId="getUserById",
     *      tags={"Users"},
     *      summary="Get user information",
     *      description="Returns user data. Admins can fetch any user. Regular users can only fetch their own profile.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(name="user_id", in="path", description="ID of user to return (UUID format)", required=true, @OA\Schema(type="string", format="uuid")),
     *      @OA\Response(response=200, description="Successful operation", @OA\JsonContent(ref="#/components/schemas/User")),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Cannot access this user's profile"),
     *      @OA\Response(response=404, description="User not found")
     * )
     */
    public function show(User $user)
    {
        /** @var \App\Models\User $authenticatedUser */
        $authenticatedUser = Auth::user();

        if ($authenticatedUser->role === 'admin' || $authenticatedUser->iduser === $user->iduser) {
            return response()->json($user->load('userInfo'));
        }

        return response()->json(['message' => 'Forbidden. You do not have permission to view this profile.'], 403);
    }

    /**
     * @OA\Put(
     *      path="/users/{user_id}/profile",
     *      operationId="updateUserProfile",
     *      tags={"Users"},
     *      summary="Update user profile information",
     *      description="Updates user's fullname, birthday, gender, bio, and preferences only. Admins can update any user. Regular users can only update their own profile.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(name="user_id", in="path", description="ID of user to update (UUID format)", required=true, @OA\Schema(type="string", format="uuid")),
     *      @OA\RequestBody(
     *          required=false,
     *          description="User profile data to update",
     *          @OA\MediaType(
     *              mediaType="application/json",
     *              @OA\Schema(
     *                  type="object",
     *                  @OA\Property(property="fullname", type="string", example="Jane Doe Updated", nullable=true, description="User's full name"),
     *                  @OA\Property(property="datebirthday", type="string", format="date", example="1991-06-16", nullable=true, description="User's date of birth"),
     *                  @OA\Property(property="gender", type="string", enum={"male", "female", "other"}, example="female", nullable=true, description="User's gender"),
     *                  @OA\Property(property="bio", type="string", nullable=true, example="An updated bio about myself.", description="User's biography"),
     *                  @OA\Property(property="preferences", type="array", @OA\Items(type="string"), nullable=true, example={"hiking", "reading"}, description="User's preferences")
     *              )
     *          )
     *      ),
     *      @OA\Response(response=200, description="Profile updated successfully", @OA\JsonContent(ref="#/components/schemas/User")),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Cannot update this user's profile"),
     *      @OA\Response(response=404, description="User not found"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function updateProfile(UpdateUserProfileRequest $request, User $user)
    {
        $validatedData = $request->validated();

        // Update User model fields
        $userDataToUpdate = [];
        $userModelFields = ['fullname', 'datebirthday', 'gender'];

        foreach ($userModelFields as $field) {
            if (array_key_exists($field, $validatedData)) {
                $userDataToUpdate[$field] = $validatedData[$field];
            }
        }

        if (!empty($userDataToUpdate)) {
            $user->update($userDataToUpdate);
        }

        // Update UserInfo model fields
        $userInfoDataToUpdate = [];
        if (array_key_exists('bio', $validatedData)) {
            $userInfoDataToUpdate['bio'] = $validatedData['bio'];
        }
        if (array_key_exists('preferences', $validatedData)) {
            $userInfoDataToUpdate['preferences'] = $validatedData['preferences'];
        }

        if (!empty($userInfoDataToUpdate)) {
            UserInfo::updateOrCreate(['user_id' => $user->iduser], $userInfoDataToUpdate);
        }

        return response()->json([
            'message' => 'Profile updated successfully',
            'user' => $user->load('userInfo')
        ]);
    }

    /**
     * @OA\Put(
     *      path="/users/{user_id}/password",
     *      operationId="changeUserPassword",
     *      tags={"Users"},
     *      summary="Change user password",
     *      description="Changes user password. Admins can change any user's password without current password. Regular users must provide current password and can only change their own.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(name="user_id", in="path", description="ID of user to update password (UUID format)", required=true, @OA\Schema(type="string", format="uuid")),
     *      @OA\RequestBody(
     *          required=true,
     *          description="Password change data",
     *          @OA\MediaType(
     *              mediaType="application/json",
     *              @OA\Schema(
     *                  type="object",
     *                  required={"new_password", "new_password_confirmation"},
     *                  @OA\Property(property="current_password", type="string", format="password", example="currentpassword123", description="Current password (required for non-admin users)"),
     *                  @OA\Property(property="new_password", type="string", format="password", example="newpassword123", description="New password (min 8 characters)"),
     *                  @OA\Property(property="new_password_confirmation", type="string", format="password", example="newpassword123", description="New password confirmation")
     *              )
     *          )
     *      ),
     *      @OA\Response(response=200, description="Password changed successfully", @OA\JsonContent(@OA\Property(property="message", type="string", example="Password changed successfully"))),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Cannot change this user's password"),
     *      @OA\Response(response=404, description="User not found"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function changePassword(ChangePasswordRequest $request, User $user)
    {
        $validatedData = $request->validated();

        // Update password
        $user->update([
            'password' => Hash::make($validatedData['new_password'])
        ]);

        // Invalidate all existing tokens for security
        $user->tokens()->delete();

        return response()->json([
            'message' => 'Password changed successfully. Please login again with your new password.'
        ]);
    }

    /**
     * @OA\Delete(
     *      path="/users/{user_id}",
     *      operationId="deleteUser",
     *      tags={"Users"},
     *      summary="Delete a user (Admin only)",
     *      description="Deletes a user. This endpoint is restricted to administrators.",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(name="user_id", in="path", description="ID of user to delete (UUID format)", required=true, @OA\Schema(type="string", format="uuid")),
     *      @OA\Response(response=200, description="User deleted successfully", @OA\JsonContent(@OA\Property(property="message", type="string", example="User deleted successfully"))),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Admin access required or cannot delete self"),
     *      @OA\Response(response=404, description="User not found")
     * )
     */
    public function destroy(User $user)
    {
        /** @var \App\Models\User $authenticatedUser */
        $authenticatedUser = Auth::user();

        if ($authenticatedUser->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. Admin access required.'], 403);
        }

        if ($authenticatedUser->iduser === $user->iduser) {
            return response()->json(['message' => 'Forbidden. You cannot delete your own account through this endpoint.'], 403);
        }

        $user->tokens()->delete();
        $user->delete();

        return response()->json(['message' => 'User deleted successfully']);
    }
}

// ============================================
// UpdateUserProfileRequest.php
// ============================================

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;

class UpdateUserProfileRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        $user = $this->route('user'); // Get user from route model binding
        $authenticatedUser = Auth::user();

        // Admin can update any user, or user can update their own profile
        return $authenticatedUser->role === 'admin' || $authenticatedUser->iduser === $user->iduser;
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'fullname' => 'sometimes|string|max:255',
            'datebirthday' => 'sometimes|date|before:today',
            'gender' => 'sometimes|in:male,female,other',
            'bio' => 'sometimes|nullable|string|max:1000',
            'preferences' => 'sometimes|nullable|array',
            'preferences.*' => 'string|max:100',
        ];
    }

    /**
     * Get custom messages for validator errors.
     */
    public function messages(): array
    {
        return [
            'fullname.string' => 'Le nom complet doit être une chaîne de caractères.',
            'fullname.max' => 'Le nom complet ne peut pas dépasser 255 caractères.',
            'datebirthday.date' => 'La date de naissance doit être une date valide.',
            'datebirthday.before' => 'La date de naissance doit être antérieure à aujourd\'hui.',
            'gender.in' => 'Le genre doit être: male, female ou other.',
            'bio.string' => 'La biographie doit être une chaîne de caractères.',
            'bio.max' => 'La biographie ne peut pas dépasser 1000 caractères.',
            'preferences.array' => 'Les préférences doivent être un tableau.',
            'preferences.*.string' => 'Chaque préférence doit être une chaîne de caractères.',
            'preferences.*.max' => 'Chaque préférence ne peut pas dépasser 100 caractères.',
        ];
    }
}

// ============================================
// ChangePasswordRequest.php
// ============================================

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class ChangePasswordRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        $user = $this->route('user'); // Get user from route model binding
        $authenticatedUser = Auth::user();

        // Admin can change any user's password, or user can change their own password
        return $authenticatedUser->role === 'admin' || $authenticatedUser->iduser === $user->iduser;
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        $user = $this->route('user');
        $authenticatedUser = Auth::user();

        $rules = [
            'new_password' => 'required|string|min:8|confirmed',
            'new_password_confirmation' => 'required|string',
        ];

        // If user is not admin and trying to change their own password, require current password
        if ($authenticatedUser->role !== 'admin' && $authenticatedUser->iduser === $user->iduser) {
            $rules['current_password'] = 'required|string';
        }

        return $rules;
    }

    /**
     * Configure the validator instance.
     */
    public function withValidator($validator)
    {
        $validator->after(function ($validator) {
            $user = $this->route('user');
            $authenticatedUser = Auth::user();

            // If not admin and changing own password, verify current password
            if ($authenticatedUser->role !== 'admin' &&
                $authenticatedUser->iduser === $user->iduser &&
                $this->filled('current_password')) {

                if (!Hash::check($this->current_password, $user->password)) {
                    $validator->errors()->add('current_password', 'Le mot de passe actuel est incorrect.');
                }
            }

            // Ensure new password is different from current password
            if ($this->filled('new_password') && Hash::check($this->new_password, $user->password)) {
                $validator->errors()->add('new_password', 'Le nouveau mot de passe doit être différent du mot de passe actuel.');
            }
        });
    }

    /**
     * Get custom messages for validator errors.
     */
    public function messages(): array
    {
        return [
            'current_password.required' => 'Le mot de passe actuel est requis.',
            'new_password.required' => 'Le nouveau mot de passe est requis.',
            'new_password.min' => 'Le nouveau mot de passe doit contenir au moins 8 caractères.',
            'new_password.confirmed' => 'La confirmation du nouveau mot de passe ne correspond pas.',
            'new_password_confirmation.required' => 'La confirmation du nouveau mot de passe est requise.',
        ];
    }
}
