import lombok.Data;
import lombok.SneakyThrows;
import org.pcap4j.core.*;
import org.pcap4j.packet.EthernetPacket;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

@Data
public class GOOSE {

    private byte[] destination = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] source = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private final byte[] type = {(byte) 0x88, (byte) 0xB8};

    private final byte[] appID = {0x00, 0x01};
    private final byte[] length = {0x00, 0x00};
    private final byte[] reserved1 = {0x00, 0x00};
    private final byte[] reserved2 = {0x00, 0x00};
    private final byte[] goosePdu = {0x61, (byte) 0x81, (byte) 0x8A};
    private byte[] timeAllowedToLive = {(byte) 0x81, 0x05};
    private final byte[] t = {(byte) 0x84, 0x08};
    private final byte[] stNum = {(byte) 0x85, 0x05};
    private final byte[] sqNum = {(byte) 0x86, 0x05};
    private final byte[] simulation = {(byte) 0x87, 0x01};
    private final byte[] confRev = {(byte) 0x88, 0x05};
    private final byte[] ndsCom = {(byte) 0x89, 0x01};
    private final byte[] numDatSetEntries = {(byte) 0x8A, 0x05};

    private final byte[] bool = {(byte) 0x83, 0x01};
    private final byte[] int32 = {(byte) 0x85, 0x05};
    private final byte[] float32 = {(byte) 0x87, 0x05};

    private final byte[] goCBRef = {(byte) 0x80, 0x00};
    private final byte[] datSet = {(byte) 0x82, 0x00};
    private final byte[] goID = {(byte) 0x83, 0x00};

    private final byte[] allDate = {(byte) 0xAB, 0x00};

    private byte[] valueGoCBRef;
    private byte[] valueDatSet;
    private byte[] valueGoID;

    private ByteBuffer valueStNum = ByteBuffer.allocate(5);
    private ByteBuffer valueSqNum = ByteBuffer.allocate(5);
    private boolean valueSimulation = false;
    private byte[] valueConfRev = {0x00, 0x00, 0x00, 0x00, 0x00};
    private boolean valueNdsCom = false;

    private byte[] valueBool = {0x01};
    private byte[] valueInt32 = {0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] valueFloat32 = {0x00, 0x00, 0x00, 0x00, 0x00};

    private ByteBuffer valueTimeAllowedToLive = ByteBuffer.allocate(5).put(new byte[]{0x00, 0x00, 0x00, 0x00, 0x06});
    private ByteBuffer valueT = ByteBuffer.allocate(8);
    private byte[] valueNumDatSetEntries = {0x00, 0x00, 0x00, 0x00, 0x00};

    private int valueAllDate;

    private List<Item> dat = new ArrayList<>();

    private ByteBuffer buffer;

    private int time = 4;
    private int delay = 2000;

    private int lenGoose;
    private int lenAllowTime;
    private int lenSq;
    private int lenData;
    private int conf;
    private int sq;
    private int st;

    private List<PcapNetworkInterface> ifs;
    private ScheduledExecutorService ses;
    private ScheduledFuture future;
    private Runnable runnable;
    private PcapHandle sendHandle;
    private EthernetPacket packet;
    private byte[] pack;

    @SneakyThrows
    public void createGOOSE(DataSet dataSet) {
        ifs = Pcaps.findAllDevs();
        PcapNetworkInterface activeInterface = null;
        for (PcapNetworkInterface pcapIface : ifs) {
            if (pcapIface != null && pcapIface.getName().contains(dataSet.getIface())) {
                activeInterface = pcapIface;
                break;
            }
        }
        assert activeInterface != null;
        sendHandle = activeInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
        createHeader(dataSet);
        createData(dataSet);
        createMessage();
    }

    @SneakyThrows
    private void createMessage() {

        runnable = () -> {
            future = ses.schedule(runnable, time, TimeUnit.MILLISECONDS);
            increaseParam();
            try {
                sendHandle.sendPacket(packet);
                valueSqNum = valueSqNum.putInt(1, ++sq);
            } catch (PcapNativeException | NotOpenException e) {
                e.printStackTrace();
            }
        };

        buffer = ByteBuffer.allocate(lenGoose);

        buffer.put(destination)
                .put(source)
                .put(type)
                .put(appID)
                .put(length)
                .put(reserved1)
                .put(reserved2)
                .put(goosePdu)
                .put(goCBRef)
                .put(valueGoCBRef)
                .put(timeAllowedToLive)
                .put(valueTimeAllowedToLive.array())
                .put(datSet)
                .put(valueDatSet)
                .put(goID)
                .put(valueGoID)
                .put(t)
                .put(valueT.array())
                .put(stNum)
                .put(valueStNum.array())
                .put(sqNum)
                .put(valueSqNum.array())
                .put(simulation)
                .put(convertingToByte(valueSimulation))
                .put(confRev)
                .put(valueConfRev)
                .put(ndsCom)
                .put(convertingToByte(valueNdsCom))
                .put(numDatSetEntries)
                .put(valueNumDatSetEntries)
                .put(allDate);
        dat.forEach(this::typeValue);
        ses = Executors.newSingleThreadScheduledExecutor();
        packet = EthernetPacket.newPacket(buffer.array(), 0, lenGoose);

        sendHandle.sendPacket(packet);
        valueSqNum = valueSqNum.putInt(1, ++sq);
        increaseParam();
        sendHandle.sendPacket(packet);
        valueSqNum = valueSqNum.putInt(1, ++sq);

        runnable.run();
    }

    private void typeValue(Item e) {
        switch (e.getType()) {
            case "Boolean" -> buffer.put(bool)
                    .put(convertingToByte(Boolean.valueOf(e.getValue())));

            case "Integer" -> buffer.put(int32).put(new byte[]{0x00})
                    .putInt(Integer.parseInt(e.getValue()));

            case "Float" -> buffer.put(float32)
                    .put(ByteBuffer.allocate(5).put(new byte[]{0x08})
                            .putFloat(Float.parseFloat(e.getValue())).array());

        }
    }

    private void createHeader(DataSet dataSet) {

        conf = 0;
        st = 0;
        sq = 0;
        st++;
        conf++;
        valueConfRev = ByteBuffer.allocate(5).putInt(1, conf).array();
        valueStNum = valueStNum.putInt(1, st);
        valueDatSet = dataSet.getDatasetName().getBytes(StandardCharsets.UTF_8);

        valueT = valueT
                .putInt((int) (Instant.now().getEpochSecond()))
                .putInt(Instant.now().getNano());

        for (int i = 0; i < destination.length; i++) {
            destination[i] = (byte) Integer.parseInt(dataSet.getMacDestination().split(":")[i], 16);
        }
        for (int i = 0; i < source.length; i++) {
            source[i] = (byte) Integer.parseInt(dataSet.getMacSource().split(":")[i], 16);
        }

        valueGoCBRef = dataSet.getGoCbRef().getBytes(StandardCharsets.UTF_8);
        valueGoID = dataSet.getGoID().getBytes(StandardCharsets.UTF_8);

        datSet[datSet.length - 1] = (byte) valueDatSet.length;
        goCBRef[goCBRef.length - 1] = (byte) valueGoCBRef.length;
        goID[goID.length - 1] = (byte) valueGoID.length;

    }

    private void createData(DataSet dataSet) {

        valueNumDatSetEntries = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00};

        dat = dataSet.getItems();

        valueNumDatSetEntries = ByteBuffer.allocate(5).putInt(1, dat.size()).array();
        valueAllDate = (byte) dat.size();

        lenAllowTime = destination.length +
                source.length +
                type.length +
                appID.length +
                length.length +
                reserved1.length +
                reserved2.length +
                goosePdu.length +
                goCBRef.length +
                valueGoCBRef.length +
                timeAllowedToLive.length;

        lenSq = lenAllowTime +
                valueTimeAllowedToLive.array().length +
                datSet.length +
                valueDatSet.length +
                goID.length +
                valueGoID.length +
                t.length +
                valueT.array().length +
                stNum.length +
                valueStNum.array().length +
                sqNum.length;

        lenData = lenSq +
                valueSqNum.array().length +
                simulation.length +
                convertingToByte(valueSimulation).length +
                confRev.length +
                valueConfRev.length +
                ndsCom.length +
                convertingToByte(valueNdsCom).length +
                numDatSetEntries.length +
                valueNumDatSetEntries.length;

        dat.forEach(this::lengthValue);

        lenGoose += lenData + allDate.length;

        length[length.length - 1] = (byte) (lenGoose - destination.length - source.length - type.length);

    }

    private void lengthValue(Item e) {
        switch (e.getType()) {
            case "Boolean" -> {
                lenGoose += bool.length + valueBool.length;
                allDate[allDate.length - 1] += bool.length + valueBool.length;
            }
            case "Integer" -> {
                lenGoose += int32.length + valueInt32.length;
                allDate[allDate.length - 1] += int32.length + valueInt32.length;
            }
            case "Float" -> {
                lenGoose += float32.length + valueFloat32.length;
                allDate[allDate.length - 1] += float32.length + valueFloat32.length;
            }
        }
    }

    @SneakyThrows
    private void increaseParam() {
        time = Math.min(time * 2, delay);
        valueTimeAllowedToLive = valueTimeAllowedToLive
                .putInt(1, (int) Math.min(time * 1.5, delay * 1.5));
        packet = EthernetPacket.newPacket(buffer.put(lenAllowTime, valueTimeAllowedToLive.array())
                .put(lenSq, valueSqNum.array()).array(), 0, lenGoose);
    }

    private byte[] convertingToByte(Boolean bool) {
        if (bool) {
            return new byte[]{0x01};
        } else {
            return new byte[]{0x00};
        }
    }

    public void setData(DataSet newData) {
        future.cancel(true);
        ses.shutdownNow();
        dat = newData.getItems();
        sq = 0;
        time = 4;
        valueT = valueT.clear()
                .putInt((int) (Instant.now().getEpochSecond()))
                .putInt(Instant.now().getNano());
        valueSqNum = valueSqNum.clear().putInt(1, sq);
        valueTimeAllowedToLive = valueTimeAllowedToLive.clear()
                .putInt(1, 6);
        valueStNum = valueStNum.putInt(1, ++st);
        this.createMessage();
    }
}
