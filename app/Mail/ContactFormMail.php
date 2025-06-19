<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

class ContactFormMail extends Mailable
{
    use Queueable, SerializesModels;

    /**
     * The contact form data.
     *
     * @var array
     */
    public $formData;

    /**
     * Create a new message instance.
     */
    public function __construct(array $formData)
    {
        $this->formData = $formData;
    }

    /**
     * Get the message envelope.
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            // Set the 'from' address to the sender's email from the form
            from: new \Illuminate\Mail\Mailables\Address($this->formData['email'], $this->formData['name']),
            // Set the 'replyTo' address to the sender's email as well
            replyTo: [
                new \Illuminate\Mail\Mailables\Address($this->formData['email'], $this->formData['name']),
            ],
            subject: 'Contact Form Submission: ' . ($this->formData['subject'] ?? 'No Subject'),
        );
    }

    /**
     * Get the message content definition.
     */
    public function content(): Content
    {
        return new Content(markdown: 'emails.contact');
    }
}
