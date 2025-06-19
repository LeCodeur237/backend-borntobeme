<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Requests\ContactFormRequest;
use App\Mail\ContactFormMail;
use Illuminate\Support\Facades\Mail;
use OpenApi\Annotations as OA;

class ContactController extends Controller
{
    /**
     * @OA\Post(
     *      path="/contact",
     *      operationId="sendContactForm",
     *      tags={"Contact"},
     *      summary="Send a contact form message",
     *      description="Allows any user to send a message via the contact form to the application owner.",
     *      @OA\RequestBody(
     *          required=true,
     *          description="Contact form data",
     *          @OA\JsonContent(
     *              required={"name","email","message"},
     *              @OA\Property(property="name", type="string", example="Visitor Name", description="Sender's name"),
     *              @OA\Property(property="email", type="string", format="email", example="visitor@example.com", description="Sender's email address"),
     *              @OA\Property(property="subject", type="string", nullable=true, example="Inquiry about services", description="Subject of the message"),
     *              @OA\Property(property="message", type="string", example="I would like to know more about...", description="The message content")
     *          )
     *      ),
     *      @OA\Response(
     *          response=200,
     *          description="Message sent successfully",
     *          @OA\JsonContent(@OA\Property(property="message", type="string", example="Your message has been sent successfully."))
     *      ),
     *      @OA\Response(response=422, description="Validation Error", @OA\JsonContent(ref="#/components/schemas/ValidationError"))
     * )
     */
    public function send(ContactFormRequest $request)
    {
        $validatedData = $request->validated();

        // Send the email to the application's configured mail.from.address
        Mail::to(config('mail.contact_form_to_address'))->send(new ContactFormMail($validatedData));

        return response()->json(['message' => 'Your message has been sent successfully.']);
    }
}
