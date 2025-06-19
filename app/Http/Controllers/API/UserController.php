<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\UserInfo;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
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
    public function show(User $user) // Route model binding will automatically fetch the user or return 404
    {
        /** @var \App\Models\User $authenticatedUser */
        $authenticatedUser = Auth::user();

        // Admin can see any user, or user can see their own profile
        // Note: $user is the $targetUser due to route model binding
        if ($authenticatedUser->role === 'admin' || $authenticatedUser->iduser === $user->iduser) {
            return response()->json($user->load('userInfo')); // Eager load userInfo
        }

        return response()->json(['message' => 'Forbidden. You do not have permission to view this profile.'], 403);
    }

    /**
     * @OA\Put(
     *      path="/users/{user_id}",
     *      operationId="updateUser",
     *      tags={"Users"},
     *      summary="Update user information",
     *      description="Updates user data. Admins can update any user (including role). Regular users can only update their own profile (excluding role).",
     *      security={{"bearerAuth":{}}},
     *      @OA\Parameter(name="user_id", in="path", description="ID of user to update (UUID format)", required=true, @OA\Schema(type="string", format="uuid")),
     *      @OA\RequestBody(
     *          required=true,
     *          description="User data to update. Use 'multipart/form-data' when uploading a profile photo.",
     *          @OA\MediaType(
     *              mediaType="multipart/form-data",
     *              @OA\Schema(
     *                  type="object",
     *                  @OA\Property(property="fullname", type="string", example="Jane Doe Updated", nullable=true, description="User's full name"),
     *                  @OA\Property(property="email", type="string", format="email", example="jane.doe.updated@example.com", nullable=true, description="User's email address"),
     *                  @OA\Property(property="datebirthday", type="string", format="date", example="1991-06-16", nullable=true, description="User's date of birth"),
     *                  @OA\Property(property="gender", type="string", enum={"male", "female", "other"}, example="female", nullable=true, description="User's gender"),
     *                  @OA\Property(property="linkphoto", type="string", format="binary", nullable=true, description="New profile photo file. Send null or omit to keep existing or remove if previously set to null."),
     *                  @OA\Property(property="password", type="string", format="password", minLength=8, example="newSecurePassword123", description="Optional: Provide to change password", nullable=true),
     *                  @OA\Property(property="password_confirmation", type="string", format="password", minLength=8, example="newSecurePassword123", description="Required if password is provided", nullable=true),
     *                  @OA\Property(property="role", type="string", enum={"user", "admin", "editor"}, example="user", description="Admin only: Can update user role", nullable=true),
     *                  @OA\Property(property="bio", type="string", nullable=true, example="An updated bio about myself."),
     *                  @OA\Property(property="preferences", type="array", @OA\Items(type="string"), nullable=true, example={"hiking", "reading_updated"})
     *              )
     *          )
     *      ),
     *      @OA\Response(response=200, description="User updated successfully", @OA\JsonContent(ref="#/components/schemas/User")),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Cannot update this user's profile/role"),
     *      @OA\Response(response=404, description="User not found"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function update(Request $request, User $user) // Route model binding for $user
    {
        /** @var \App\Models\User $authenticatedUser */
        $authenticatedUser = Auth::user();

        // Authorization: Admin can update any user, or user can update their own profile
        if (!($authenticatedUser->role === 'admin' || $authenticatedUser->iduser === $user->iduser)) {
            return response()->json(['message' => 'Forbidden. You do not have permission to update this profile.'], 403);
        }

        $rules = [
            'fullname' => 'sometimes|required|string|max:255',
            'email' => ['sometimes', 'required', 'string', 'email', 'max:255', Rule::unique('users')->ignore($user->iduser, 'iduser')],
            'datebirthday' => 'sometimes|required|date',
            'gender' => ['sometimes', 'required', 'string', Rule::in(['male', 'female', 'other'])],
            'linkphoto' => 'nullable|image|mimes:jpeg,png,jpg,gif,svg|max:2048', // Updated for image upload
            'password' => 'nullable|string|min:8|confirmed',
            // UserInfo fields
            'bio' => 'nullable|string|max:5000',
            'preferences' => 'nullable|array',
            'preferences.*' => 'sometimes|string|max:255', // Ensures each item in the array is a string
        ];

        // Only admin can change the role
        if ($authenticatedUser->role === 'admin') {
            $rules['role'] = ['sometimes', 'required', 'string', Rule::in(['user', 'admin', 'editor'])];
        } else {
            // If a non-admin tries to update role, it will be ignored (or you can explicitly forbid it)
            if ($request->has('role') && $request->input('role') !== $user->role) {
                 return response()->json(['message' => 'Forbidden. You cannot change your own role.'], 403);
            }
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $validatedData = $validator->validated();

        // Prepare data for User model update
        // Explicitly list fields to prevent mass assignment issues with file objects
        $userDataToUpdate = [];
        $userModelFields = ['fullname', 'email', 'datebirthday', 'gender'];
        foreach ($userModelFields as $field) {
            if (array_key_exists($field, $validatedData)) {
                $userDataToUpdate[$field] = $validatedData[$field];
            }
        }

        // Handle linkphoto (file upload or explicit null for removal)
        if ($request->hasFile('linkphoto')) {
            if ($user->linkphoto) { // Check if there's an old photo
                $basePublicUrl = rtrim(Storage::disk('public')->url(''), '/');
                if (str_starts_with($user->linkphoto, $basePublicUrl . '/')) {
                    $oldRelativePath = substr($user->linkphoto, strlen($basePublicUrl) + 1);
                    Storage::disk('public')->delete($oldRelativePath);
                }
            }
            $filePath = $request->file('linkphoto')->store('profil', 'public'); // Store in 'storage/app/public/profil'
            $userDataToUpdate['linkphoto'] = Storage::disk('public')->url($filePath); // Get public URL
        } elseif (array_key_exists('linkphoto', $validatedData) && is_null($validatedData['linkphoto'])) {
            // This case handles if linkphoto is explicitly sent as null (e.g., to remove it).
            // $validatedData['linkphoto'] would be null here if 'nullable|image' passed with a null input.
            if ($user->linkphoto) {
                $basePublicUrl = rtrim(Storage::disk('public')->url(''), '/');
                if (str_starts_with($user->linkphoto, $basePublicUrl . '/')) {
                    $oldRelativePath = substr($user->linkphoto, strlen($basePublicUrl) + 1);
                    Storage::disk('public')->delete($oldRelativePath);
                }
            }
            $userDataToUpdate['linkphoto'] = null;
        }
        // If 'linkphoto' was not sent in the request at all, it won't be in $userDataToUpdate,
        // and the existing photo will remain unchanged.

        if (!empty($validatedData['password'])) { // Only update password if provided
            $userDataToUpdate['password'] = $validatedData['password']; // Hashing is handled by mutator in User model
        }
        // Role update logic
        if ($authenticatedUser->role === 'admin' && isset($validatedData['role'])) {
            $userDataToUpdate['role'] = $validatedData['role'];
        }

        if (!empty($userDataToUpdate)) {
            $user->update($userDataToUpdate);
        }

        // Prepare data for UserInfo model update
        $userInfoDataToUpdate = [];
        if (array_key_exists('bio', $validatedData)) {
            $userInfoDataToUpdate['bio'] = $validatedData['bio'];
        }
        if (array_key_exists('preferences', $validatedData)) {
            $userInfoDataToUpdate['preferences'] = $validatedData['preferences'];
        }

        // Update or create UserInfo if bio or preferences fields were part of the request
        if (array_key_exists('bio', $validatedData) || array_key_exists('preferences', $validatedData)) {
            UserInfo::updateOrCreate(['user_id' => $user->iduser], $userInfoDataToUpdate);
        }

        return response()->json($user->load('userInfo')); // Eager load userInfo for the response
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
    public function destroy(User $user) // Route model binding for $user
    {
        /** @var \App\Models\User $authenticatedUser */
        $authenticatedUser = Auth::user();

        if ($authenticatedUser->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. Admin access required.'], 403);
        }

        // $user is the $targetUser due to route model binding.
        // Laravel returns 404 automatically if user not found by {user} in route.

        // Prevent admin from deleting themselves through this endpoint for safety
        // They can be deleted via direct database manipulation or a dedicated super-admin tool if needed.
        if ($authenticatedUser->iduser === $user->iduser) {
            return response()->json(['message' => 'Forbidden. You cannot delete your own account through this endpoint.'], 403);
        }

        $user->tokens()->delete(); // Invalidate all tokens for the user being deleted
        $user->delete();

        return response()->json(['message' => 'User deleted successfully']);
    }
}
