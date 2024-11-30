package me.appsec.services;

import jakarta.ejb.Stateless;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Stateless
public class SteganographyService {
    public byte[] hideMessage(String message, BufferedImage theImage, String secretKey) throws IOException {
        int[] messageLengthBits = getMessageLengthBits(message);
        embedMessageLength(theImage, messageLengthBits);

        int[] messageBits = convertStringToBits(message);
        int[] pixelPositions = getPixelPositions(secretKey, messageBits.length);
        embedMessageBits(theImage, messageBits, pixelPositions);

        return convertImageToByteArray(theImage);
    }
    public String extractMessage(BufferedImage theImage, String secretKey) {
        int messageLength = extractMessageLength(theImage);
        int[] pixelPositions = getPixelPositions(secretKey, messageLength * 8);
        String messageBits = extractMessageBits(theImage, pixelPositions);

        return convertBitsToString(messageBits);
    }

    private int[] getMessageLengthBits(String message) {
        String lengthBinary = Integer.toBinaryString(message.length());
        while (lengthBinary.length() < 8) {
            lengthBinary = '0' + lengthBinary;
        }
        return lengthBinary.chars().map(c -> c - '0').toArray();
    }
    private void embedMessageLength(BufferedImage theImage, int[] lengthBits) {
        int bitIndex = 0;

        for (int x = 0; x < theImage.getWidth() && bitIndex < lengthBits.length; x++) {
            for (int y = 0; y < theImage.getHeight() && bitIndex < lengthBits.length; y++) {
                int currentPixel = theImage.getRGB(x, y);
                int red = (currentPixel >> 16) & 255;
                int green = (currentPixel >> 8) & 255;
                int blue = currentPixel & 255;

                int newBlue = modifyLeastSignificantBit(blue, lengthBits[bitIndex]);
                int newPixel = (255 << 24) | (red << 16) | (green << 8) | newBlue;

                theImage.setRGB(x, y, newPixel);
                bitIndex++;
            }
        }
    }
    private void embedMessageBits(BufferedImage theImage, int[] messageBits, int[] pixelPositions) {
        int bitIndex = 0;

        for (int pixelIndex : pixelPositions) {
            if (bitIndex >= messageBits.length) break;

            int x = pixelIndex % theImage.getWidth();
            int y = pixelIndex / theImage.getWidth();

            int currentPixel = theImage.getRGB(x, y);
            int red = (currentPixel >> 16) & 255;
            int green = (currentPixel >> 8) & 255;
            int blue = currentPixel & 255;

            int newBlue = modifyLeastSignificantBit(blue, messageBits[bitIndex]);
            int newPixel = (255 << 24) | (red << 16) | (green << 8) | newBlue;

            theImage.setRGB(x, y, newPixel);
            bitIndex++;
        }
    }
    private int extractMessageLength(BufferedImage theImage) {
        StringBuilder lengthBits = new StringBuilder();

        for (int x = 0; x < theImage.getWidth() && lengthBits.length() < 8; x++) {
            for (int y = 0; y < theImage.getHeight() && lengthBits.length() < 8; y++) {
                int currentPixel = theImage.getRGB(x, y);
                int blue = currentPixel & 255;
                lengthBits.append(blue & 1);
            }
        }
        return Integer.parseInt(lengthBits.toString(), 2);
    }
    private String extractMessageBits(BufferedImage theImage, int[] pixelPositions) {
        StringBuilder messageBits = new StringBuilder();

        for (int pixelIndex : pixelPositions) {
            int x = pixelIndex % theImage.getWidth();
            int y = pixelIndex / theImage.getWidth();

            int currentPixel = theImage.getRGB(x, y);
            int blue = currentPixel & 255;

            messageBits.append(blue & 1);
        }
        return messageBits.toString();
    }
    private int modifyLeastSignificantBit(int value, int bit) {
        return (value & ~1) | bit;
    }
    private String convertBitsToString(String bits) {
        StringBuilder message = new StringBuilder();

        for (int i = 0; i < bits.length(); i += 8) {
            String byteStr = bits.substring(i, i + 8);
            int charCode = Integer.parseInt(byteStr, 2);
            message.append((char) charCode);
        }
        return message.toString();
    }
    public static int[] convertStringToBits(String msg) {
        int[] bits = new int[msg.length() * 8];
        int index = 0;

        for (char c : msg.toCharArray()) {
            String binaryString = String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0');
            for (char bit : binaryString.toCharArray()) {
                bits[index++] = bit - '0';
            }
        }
        return bits;
    }
    private byte[] convertImageToByteArray(BufferedImage image) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ImageIO.write(image, "png", byteArrayOutputStream);
        return byteArrayOutputStream.toByteArray();
    }
    public static int[] getPixelPositions(String secretKey, int numPixelsRequired) {
        int[] secretKeyBits = convertStringToBits(secretKey);
        int onesCount = (int) java.util.Arrays.stream(secretKeyBits).filter(bit -> bit == 1).count();

        if (onesCount >= numPixelsRequired && onesCount % 8 == 0) {
            return getFirstOnesPositions(secretKeyBits, numPixelsRequired);
        } else {
            int[] extendedKeyBits = extendKeyBits(secretKeyBits, numPixelsRequired, onesCount);
            return getFirstOnesPositions(extendedKeyBits, numPixelsRequired);
        }
    }
    private static int[] getFirstOnesPositions(int[] secretKeyBits, int numPixelsRequired) {
        List<Integer> positions = new ArrayList<>();

        for (int i = 0; i < secretKeyBits.length && positions.size() < numPixelsRequired; i++) {
            if (secretKeyBits[i] == 1) {
                positions.add(i + 8);
            }
        }

        return positions.stream().mapToInt(Integer::intValue).toArray();
    }
    private static int[] extendKeyBits(int[] keyBits, int numPixelsRequired, int onesCount) {
        List<Integer> extendedBits = new ArrayList<>();
        for (int bit : keyBits) {
            extendedBits.add(bit);
        }
        while (onesCount < numPixelsRequired || onesCount % 8 != 0) {
            for (int bit : keyBits) {
                extendedBits.add(bit);
                if (bit == 1) {
                    onesCount++;
                }
                if (onesCount >= numPixelsRequired && onesCount % 8 == 0) {
                    break;
                }
            }
        }
        return extendedBits.stream().mapToInt(Integer::intValue).toArray();
    }
}
