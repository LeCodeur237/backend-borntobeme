<x-mail::message>
# New Contact Form Submission

You have received a new message from your contact form.

**Name:** {{ $formData['name'] }}

**Email:** {{ $formData['email'] }}

**Subject:** {{ $formData['subject'] ?? 'N/A' }}

**Message:**

{{ $formData['message'] }}

Thanks,
{{ config('app.name') }}
</x-mail::message>
