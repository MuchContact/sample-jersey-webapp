package com.sample.jersey.app;

import com.sample.jersey.app.tools.CryptUtil;
import org.apache.commons.io.IOUtils;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Objects;

@Path("/encrypt")
public class EncryptResource {

    private File file;
    private File file1;

    public EncryptResource() {
        try {
            InputStream p12Stream = getClass().getClassLoader().getResourceAsStream("web-client.p12");
            file = stream2file(p12Stream, "web-client", ".p12");
            InputStream cerFileNameStream = getClass().getClassLoader().getResourceAsStream("web-client11.cer");
            file1 = stream2file(cerFileNameStream, "web-client11", ".cer");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response getMusics(Map<String, Object> form,
                              @Context UriInfo uri) throws IOException {
        String body = (String) form.get("body");
        if (body == null)
            return Response.status(Response.Status.BAD_REQUEST).build();

        String[] str_arr = CryptUtil.encrypt(file.getPath(), file1.getPath(), body);
        System.out.println(str_arr[0]);
        return Response.ok(String.format("{\"fmsg\":\"%s\", \"gmsg\":\"%s\"}", str_arr[0], str_arr[1])).build();
    }

    public static File stream2file(InputStream in, String fileName, String suffix) throws IOException {
        final File tempFile = File.createTempFile(fileName, suffix);
        tempFile.deleteOnExit();
        try (FileOutputStream out = new FileOutputStream(tempFile)) {
            IOUtils.copy(in, out);
        }
        return tempFile;
    }
}
