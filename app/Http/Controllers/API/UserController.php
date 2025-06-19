<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\UserInfo;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
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
    public function show(string $userId)
    {
        $targetUser = User::find($userId);

        if (!$targetUser) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $authenticatedUser = Auth::user();

        // Admin can see any user, or user can see their own profile
        if ($authenticatedUser->role === 'admin' || $authenticatedUser->iduser === $targetUser->iduser) {
            return response()->json($targetUser);
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
     *          description="User data to update",
     *          @OA\JsonContent(
     *              type="object",
     *              @OA\Property(property="fullname", type="string", example="Jane Doe Updated"),
     *              @OA\Property(property="email", type="string", format="email", example="jane.doe.updated@example.com"),
     *              @OA\Property(property="datebirthday", type="string", format="date", example="1991-06-16"),
     *              @OA\Property(property="gender", type="string", enum={"male", "female", "other"}, example="female"),
     *              @OA\Property(property="linkphoto", type="string", format="url", nullable=true, example="http://example.com/new_photo.jpg"),
     *              @OA\Property(property="password", type="string", format="password", minLength=8, example="newSecurePassword123", description="Optional: Provide to change password"),
     *              @OA\Property(property="password_confirmation", type="string", format="password", minLength=8, example="newSecurePassword123", description="Required if password is provided"),
     *              @OA\Property(property="role", type="string", enum={"user", "admin", "editor"}, example="user", description="Admin only: Can update user role"),
     *              @OA\Property(property="bio", type="string", nullable=true, example="An updated bio about myself."),
     *              @OA\Property(property="preferences", type="array", @OA\Items(type="string"), nullable=true, example={"hiking", "reading_updated"})
     *          )
     *      ),
     *      @OA\Response(response=200, description="User updated successfully", @OA\JsonContent(ref="#/components/schemas/User")),
     *      @OA\Response(response=401, description="Unauthenticated"),
     *      @OA\Response(response=403, description="Forbidden - Cannot update this user's profile/role"),
     *      @OA\Response(response=404, description="User not found"),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function update(Request $request, string $userId)
    {
        $targetUser = User::find($userId);

        if (!$targetUser) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $authenticatedUser = Auth::user();

        // Authorization: Admin can update any user, or user can update their own profile
        if (!($authenticatedUser->role === 'admin' || $authenticatedUser->iduser === $targetUser->iduser)) {
            return response()->json(['message' => 'Forbidden. You do not have permission to update this profile.'], 403);
        }

        $rules = [
            'fullname' => 'sometimes|required|string|max:255',
            'email' => ['sometimes', 'required', 'string', 'email', 'max:255', Rule::unique('users')->ignore($targetUser->iduser, 'iduser')],
            'datebirthday' => 'sometimes|required|date',
            'gender' => ['sometimes', 'required', 'string', Rule::in(['male', 'female', 'other'])],
            'linkphoto' => 'nullable|string|url|max:255',
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
            if ($request->has('role') && $request->input('role') !== $targetUser->role) {
                 return response()->json(['message' => 'Forbidden. You cannot change your own role.'], 403);
            }
        }

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $validatedData = $validator->validated();

        // Prepare data for User model update
        $userDataToUpdate = [];
        if (isset($validatedData['fullname'])) $userDataToUpdate['fullname'] = $validatedData['fullname'];
        if (isset($validatedData['email'])) $userDataToUpdate['email'] = $validatedData['email'];
        if (isset($validatedData['datebirthday'])) $userDataToUpdate['datebirthday'] = $validatedData['datebirthday'];
        if (isset($validatedData['gender'])) $userDataToUpdate['gender'] = $validatedData['gender'];
        if (array_key_exists('linkphoto', $validatedData)) $userDataToUpdate['linkphoto'] = $validatedData['linkphoto']; // Handle null linkphoto

        if (!empty($validatedData['password'])) { // Only update password if provided
            $userDataToUpdate['password'] = $validatedData['password']; // Hashing is handled by mutator in User model
        }
        // Role update logic
        if ($authenticatedUser->role === 'admin' && isset($validatedData['role'])) {
            $userDataToUpdate['role'] = $validatedData['role'];
        }

        if (!empty($userDataToUpdate)) {
            $targetUser->update($userDataToUpdate);
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
            UserInfo::updateOrCreate(['user_id' => $targetUser->iduser], $userInfoDataToUpdate);
        }

        return response()->json($targetUser->load('userInfo')); // Eager load userInfo for the response
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
    public function destroy(string $userId)
    {
        $authenticatedUser = Auth::user();

        if ($authenticatedUser->role !== 'admin') {
            return response()->json(['message' => 'Forbidden. Admin access required.'], 403);
        }

        $targetUser = User::find($userId);

        if (!$targetUser) {
            return response()->json(['message' => 'User not found'], 404);
        }

        // Prevent admin from deleting themselves through this endpoint for safety
        // They can be deleted via direct database manipulation or a dedicated super-admin tool if needed.
        if ($authenticatedUser->iduser === $targetUser->iduser) {
            return response()->json(['message' => 'Forbidden. You cannot delete your own account through this endpoint.'], 403);
        }

        $targetUser->tokens()->delete(); // Invalidate all tokens for the user being deleted
        $targetUser->delete();

        return response()->json(['message' => 'User deleted successfully']);
    }
}
