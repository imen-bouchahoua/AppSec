package me.appsec.controllers;

import jakarta.ejb.EJB;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.EntityPart;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import me.appsec.security.Secured;
import me.appsec.services.SteganographyService;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Path("/")
@Secured
public class SteganographyController {
    @EJB
    SteganographyService steganographyService;

    @GET
    public String helloWord(){
        return "Hello word!";
    }
    @POST
    @Path("/hide")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.TEXT_PLAIN)
    public Response hideMessage(
            @FormParam("image") EntityPart image,
            @FormParam("message") String message,
            @FormParam("key") String key) throws IOException {

        String msg = URLDecoder.decode(message, StandardCharsets.UTF_8);
        validateInputsHide(image,msg, key);

        BufferedImage img = ImageIO.read(image.getContent());

        byte[] markedImagePath = steganographyService.hideMessage(msg, img, key);

        if (markedImagePath == null) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("An error occurred while hiding the message in the image.")
                    .build();
        }

        return Response.ok("data:image/png;base64,"+Base64.getEncoder().encodeToString(markedImagePath))
                .header("Content-Disposition", "attachment; filename=hidden_message_image.png")
                .build();
    }
    @POST
    @Path("/extract")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.TEXT_PLAIN)
    public Response extractMessage(
            @FormParam("image") EntityPart image,
            @FormParam("key") String key
    ) throws IOException {
        validateInputsExtract(image,key);
        BufferedImage img = ImageIO.read(image.getContent());
        String extractedMessage = steganographyService.extractMessage(img, key);

        return Response.ok(extractedMessage).build();
    }

    private void validateInputsHide(EntityPart image, String message, String key) {
        //System.out.println("Message content: " + message);
        //System.out.println("len"+ message.length());

        if (image == null || message == null || key == null) {
            throw new BadRequestException("At least one of the fields (image, message, key) is not defined.");
        }
        if (key.isEmpty()) {
            throw new BadRequestException("Key is empty.");
        }

        if (message.length()> 255) {
            throw new BadRequestException("Message exceeded 255 characters.");
        }
        if (!isImageFile(image)) {
            throw new BadRequestException("Only image files (PNG, JPEG, JPG) are allowed.");
        }
    }
    private void validateInputsExtract(EntityPart image, String key) {
        if (image == null || key == null) {
            throw new BadRequestException("Both 'image' and 'key' fields must be provided.");
        }
        if (!isImageFile(image)) {
            throw new BadRequestException("Only image files (PNG, JPEG, JPG) are allowed.");
        }
    }
    private boolean isImageFile(EntityPart part) {
        String contentType = part.getHeaders().getFirst("Content-Type");
        if (contentType == null) {
            return false;
        }
        contentType = contentType.toLowerCase();
        return contentType.equals("image/png") ||
                contentType.equals("image/jpeg") ||
                contentType.equals("image/jpg");
    }
}
