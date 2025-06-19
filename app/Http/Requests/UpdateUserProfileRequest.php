<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;
use App\Models\User; // Required for type hinting the route model bound user

class UpdateUserProfileRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize(): bool
    {
        /** @var User $authenticatedUser */
        $authenticatedUser = Auth::user();

        /** @var User $targetUser */
        // The 'user' parameter comes from the route segment {user}
        // and is resolved to a User model instance by route model binding.
        $targetUser = $this->route('user');

        // Admin can update any user, or user can update their own profile.
        return $authenticatedUser->role === 'admin' || $authenticatedUser->iduser === $targetUser->iduser;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array|string>
     */
    public function rules(): array
    {
        return [
            'fullname' => 'sometimes|string|max:255',
            'datebirthday' => 'sometimes|nullable|date', // Allow clearing birthday
            'gender' => ['sometimes', 'string', 'in:male,female,other'],
            'linkphoto' => 'nullable|image|mimes:jpeg,png,jpg,gif,svg|max:2048',
            // UserInfo fields
            'bio' => 'nullable|string|max:5000',
            'preferences' => 'nullable|array',
            'preferences.*' => 'sometimes|string|max:255',
        ];
    }

    /**
     * Get custom messages for validator errors.
     *
     * @return array
     */
    public function messages(): array
    {
        return [
            'gender.in' => 'The selected gender is invalid. Allowed values are male, female, other.',
        ];
    }
}
